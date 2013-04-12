/* erebus - a modular, high performance server
 *
 * Copyright (c) 2011 J.J.
 * All rights reserved.
 *
 * $Id$
 * $DateTime$
 */

#include <libgpp/compiler_config.hpp>

#include <boost/shared_ptr.hpp>
#include <boost/enable_shared_from_this.hpp>
#include <boost/unordered_map.hpp>
#include <boost/thread/mutex.hpp>
#include <boost/bind.hpp>
#include <boost/function.hpp>
#include <boost/format.hpp>
#include <boost/thread.hpp>
#include <boost/asio.hpp>

#include <openssl/sha.h>
#include <openssl/rc4.h>

#include <libgpp/utils.hpp>

#define DEBUG_BUILD

/*
  one io_service, thread pool design

  initial login exchange -

  client ---[    hello      ]--> server
  client <--[  nonce info   ]--- server
  client ---[     login     ]--> server
  client <--[  login_reply  ]--- server

  after login -

  client ---[ join_channel  ]--> server
  client ---[    message    ]--> server

  admin commands -
  
  client ---[     oper      ]--> server
  client <--[  oper_reply   ]--- server

  make_oper_hash
  oper encode(oper_hash)
  list_opers
  list_channels
  list_users, list_users_reply (ie. users -l 10, users -h *.net, users -c channel -l 10, users -c channel -h *.net)
  enable_events (joins, parts, quits)

  every ping_interval -

  client <--[     ping      ]--- server
  client ---[     pong      ]--> server

  hello_packet - 

  {
    <packet_type_hello>:2
    <total_packet_length> (excludes this 2 bytes)
    <# of random pads> max - 5, min - 2
    <random pad #1 length>
    <random pad #1>
    ...
    <random pad #n length>
    <random pad #n>
  }

  login_packet

  {
    <packet_type_login>:2
    <major_version>:1
    <minor_version>:1
    <revision>:2
    ...
  }

  login_reply -

  {
    <packet_type_login_reply>:2
    <login_reply_type>:1
    {
      <login_reply_specific_data>
      on login success:
      {
        <size>:2
        <ip_address_string>:size
      }

      on login failure:
      {
        <error_code>:2
      }
    }
  }

  ping -
  
  {
    <packet_type_ping>:2
  }

  pong -

  {
    <packet_type_pong>:2
  }

  commands -

  {
    <packet_type_command>:2
    <command_type>:2
    <command specific data>:variable
  }

*/

enum os_types
{
  windows,
  linux,
  freebsd,
  mac_osx,
};

class erebus_session;

class erebus_server_session_interface
{
public:
  virtual void remove_session(boost::shared_ptr<erebus_session>& session) = 0;
};

/*
  register_packet_handler(nonce_info, boost::bind(&erebus_session::handle_nonce_info, this));

*/

class erebus_session : public boost::enable_shared_from_this<erebus_session>
{
  /* function handler typedefs */
  typedef boost::function<void()> post_hook_handler_t;
  
  typedef enum
  {
    initialized,
    key_exchanged,
    authenticated
  } state_t;

  /* generate unique hash for these packet types */
  typedef enum
  {
    hello,
    nonce_info,
    auth_request,
    auth_reply,
    command,
    command_reply,
    ping,
    pong,
    event
  } packet_t;

public:
  erebus_session(boost::asio::io_service& io_service,
    erebus_server_session_interface& server, boost::uint32_t session_id)
    : io_service_(io_service),
      socket_(io_service),
      read_timer_(io_service),
      server_(server),
      session_id_(session_id),
      state_(initialized)
  {      
    if (packet_handlers_.empty())
    {
      register_packet_handler(
        hello,
        boost::bind(&erebus_session::handle_hello, _1)
      );

      register_packet_handler(
        auth_request, 
        boost::bind(&erebus_session::handle_auth_request, _1)
      );
    }
  }

  void register_packet_handler(packet_t packet, 
    const post_hook_handler_t& handler)
  {
    packet_handlers_.insert(
      std::pair<packet_t, post_hook_handler_t>(packet, handler)
    );
  }

  void call_packet_handler(packet_t packet)
  {
    packet_handlers_.find();
  }

  void run()
  {
    read_packet();
  }

  boost::uint32_t get_session_id() const
  {
    return session_id_;
  }

  boost::asio::ip::tcp::socket& socket()
  {
    return socket_;
  }

private:  
  void handle_auth_request()
  {
    assert_condition(state_ == key_exchanged);

    /* login stuff */

    state_ = authenticated;
  }

  void handle_hello()
  {
    assert_condition(state_ == initialized);

    read_buffer_.print_output();

    boost::uint8_t number_of_pads = read_buffer_.pop_front_uint8();


    printf("number of pads %d\n", number_of_pads);
    assert_condition(number_of_pads > 1 && number_of_pads < 6);
  
    while(number_of_pads--)
    {
      boost::uint8_t pad_length = read_buffer_.pop_front_uint8();
      assert_condition((pad_length < 16) && (pad_length > 4));
      read_buffer_.pop_front_buffer(pad_length);
    }

    printf("received valid hello packet\n");

    libgpp::byte_buffer buffer;
    libgpp::byte_buffer nonce = libgpp::utils::make_random(8);

    SHA_CTX sha_ctx;
    boost::uint8_t digest[20];

    SHA1_Init(&sha_ctx);
    SHA1_Update(&sha_ctx, &nonce[0], nonce.size());
    SHA1_Final(digest, &sha_ctx);

    RC4_set_key(&rc4_key_, 20, digest);

    buffer.push_back_uint32(nonce_info);
    buffer.push_back_uint16(nonce.size());
    buffer.push_back_data(nonce);

    state_ = key_exchanged;

    write_packet(buffer);
  }

  void read_packet()
  {
    read_buffer_.resize(128);
    socket_.async_read_some(
      boost::asio::buffer(read_buffer_.v()),
      boost::bind(
        &erebus_session::handle_read_packet, shared_from_this(),
        boost::asio::placeholders::error,
        boost::asio::placeholders::bytes_transferred
      )
    );

    /* set read timeout */
    read_timer_.expires_from_now(boost::posix_time::seconds(10));
    read_timer_.async_wait(
      boost::bind(
        &erebus_session::handle_read_timeout, 
        shared_from_this(),
        boost::asio::placeholders::error
      )
    );
  }

  void handle_read_timeout(const boost::system::error_code& error)
  {
    if (!error)
    {
      boost::system::error_code ec;

#if defined(BOOST_MSVC)
#pragma warning(push)
  #pragma warning(disable : 4996)
#endif /* defined(BOOST_MSVC) */
      socket_.cancel(ec);
#if defined(BOOST_MSVC)
  #pragma warning(pop)
#endif /* defined(BOOST_MSVC) */
      socket_.close(ec);
    }
  }

  void handle_read_packet(const boost::system::error_code& error,
    std::size_t bytes_transferred)
  {
    printf("handle read packet - %d\n", bytes_transferred);
    read_timer_.cancel();
    boost::system::error_code return_error = error;
    if (!error)
    {
      read_buffer_.resize(bytes_transferred);

      try
      {
        if (is_encrypted_session_)
        {
          RC4(
          //decrypt_packet(read_buffer_);
        }

        boost::uint16_t packet_type = read_buffer_.pop_front_uint16();
        boost::uint16_t packet_length = read_buffer_.pop_front_uint16();
        
        call_packet_handler(packet_type);

        return;
      }
      catch(const libgpp::error::basic_exception& e)
      {
        return_error = e.error_code();
      }
    }
    
    server_.remove_session(shared_from_this());
  }

  void write_packet(const post_hook_handler_type& handler, 
    const libgpp::byte_buffer& buffer, bool is_read_handler_called = true)
  {
    try
    {
      write_buffer_ = buffer;
      write_buffer_.push_front_uint16(buffer.size());

      if (is_encrypted_session_)
      {
        //encrypt_packet(write_buffer_);
      }

      boost::asio::async_write(
        socket_, 
        boost::asio::buffer(write_buffer_.v()),
        boost::asio::transfer_all(),
        boost::bind(
          &erebus_session::handle_write_packet, shared_from_this(),
          boost::asio::placeholders::error,
          boost::asio::placeholders::bytes_transferred,
          handler,
          is_read_handler_called
        )
      );
    }
    catch(const libgpp::error::basic_exception&)
    {
      server_.remove_session(shared_from_this());
    }
  }

  void handle_write_packet(const boost::system::error_code& error,
    std::size_t bytes_transferred, const post_hook_handler_type& handler,
    bool is_read_handler_called)
  {
    boost::system::error_code return_error = error;
    if (!error)
    {
      if (is_read_handler_called)
      {
        read_buffer_.resize(128);
        socket_.async_read_some(
          boost::asio::buffer(read_buffer_.v()),
          boost::bind(
            &erebus_session::handle_read_packet, shared_from_this(),
            boost::asio::placeholders::error,
            boost::asio::placeholders::bytes_transferred,
            handler
          )
        );
        return;
      }
      else
      {
        try
        {
          handler();
          return;
        }
        catch(const libgpp::error::basic_exception& e)
        {
          return_error = e.error_code();
        }
      }
    }
    
    server_.remove_session(shared_from_this());
  }

private:
  boost::asio::io_service& io_service_;
  boost::asio::ip::tcp::socket socket_;
  boost::asio::deadline_timer read_timer_;
  erebus_server_session_interface &server_;
  const boost::uint32_t session_id_;
  libgpp::byte_buffer read_buffer_;
  libgpp::byte_buffer write_buffer_;

  RC4_KEY rc4_key_;
  
  bool is_encrypted_session_;
  state_t state_;

  static boost::unordered_map<packet_type, post_hook_handler_t> packet_handlers_;
  static boost::mutex mutex_;
};

class erebus_server : public erebus_server_session_interface
{
private:
  typedef boost::shared_ptr<erebus_session> erebus_session_ptr;
  typedef boost::unordered_map<boost::uint32_t, erebus_session_ptr> session_map_type;

public:
  erebus_server(boost::asio::io_service& io_service, boost::uint16_t port)
    : io_service_(io_service),
      port_(port),
      acceptor_(
        io_service, boost::asio::ip::tcp::endpoint(
        boost::asio::ip::tcp::v4(), port)
      )
  {
  }

  ~erebus_server()
  {
  }
  
  void run()
  {
    add_session();
  }

  void remove_session(erebus_session_ptr& session)
  {
    boost::mutex::scoped_lock lock(mutex_);
    sessions_.erase(session->get_session_id());
  }

private:
  void add_session()
  {
    boost::shared_ptr<erebus_session> session;
    boost::uint32_t session_id;
    std::pair<session_map_type::iterator, bool> result;

    {
      boost::mutex::scoped_lock lock(mutex_);
      do 
      {
        /* generate unique session id */
        session_id = libgpp::utils::make_random(0xffffffff) + 0xffff;
        result = sessions_.insert(std::make_pair(session_id, session));
      }
      while(result.second == false);
    }

    session.reset(new erebus_session(io_service_, *this, session_id));

    acceptor_.async_accept(
      session->socket(),
      boost::bind(
        &erebus_server::handle_accept, this, 
        boost::asio::placeholders::error,
        session
      )
    );
  }

  void handle_accept(const boost::system::error_code& error,
    erebus_session_ptr& session)
  {
    if (!error)
    {
      printf("client connected thread id: %x\n", boost::this_thread::get_id());
      /* post session as work so we can return immediately */
      io_service_.post(
        boost::bind(&erebus_session::run, session)
      );
    }
    else
    {
      remove_session(session);
    }

    add_session();
  }

private:
  boost::asio::io_service& io_service_;
  const boost::uint16_t port_;
  boost::asio::ip::tcp::acceptor acceptor_;

  session_map_type sessions_;
  boost::mutex mutex_;
};

void formatter(const boost::format& format)
{
  std::cout << format.str() << std::endl;
}

/* LIBPP_LOG("debug") << boost::format("test") << std::endl; */

#if defined(BOOST_WINDOWS) && !defined(DEBUG_BUILD)
  #pragma comment(linker, "/subsystem:windows")
  int __stdcall WinMain(HINSTANCE, HINSTANCE, LPSTR, int)
#else
  int main(int argc, char **argv)
#endif /* defined(BOOST_WINDOWS) && !defined(DEBUG_BUILD) */
{
  try
  {
    boost::asio::io_service io_service;
    erebus_server server(io_service, 1337);

    server.run();
    
    boost::thread_group service_thread_group;

    for(int i=0; i<5; i++)
    {
      service_thread_group.create_thread(
        boost::bind(
          &boost::asio::io_service::run, boost::ref(io_service)
        )
      );
    }

    service_thread_group.join_all();
  }
  catch(const std::exception&) 
  {
  }

  return 0;
}
