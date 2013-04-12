/* erebus client
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
  client ---[key exchange dh]--> server (64 bit key)
  client <--[key exchange dh]--- server
  client ---[     login     ]--> server
  client <--[  login_reply  ]--- server

  after login -

  client ---[ join_channel  ]--> server
  client ---[    message    ]--> server
*/

enum os_types
{
  windows,
  linux,
  freebsd,
  mac_osx,
};

class erebus_client : public boost::enable_shared_from_this<erebus_client>
{
  /* function handler typedefs */
  typedef boost::function<void()> post_hook_handler_type;

  enum packet_types 
  {
    nonce_info,
    nonce_info_reply,
    login_request,
    login_reply,
    command_request,
    command_reply,
    ping,
    pong,
    event
  };

public:
  erebus_client(boost::asio::io_service& io_service)
    : io_service_(io_service),
      socket_(io_service),
      read_timer_(io_service)
  {
    /* store handlers */
  }

  void run()
  {
    boost::asio::ip::tcp::endpoint endpoint(
      boost::asio::ip::address::from_string("127.0.0.1"), 1337
    );

    socket_.async_connect(
      endpoint,
      boost::bind(&erebus_client::handle_connect, this, _1)
    ); 
  }

  boost::asio::ip::tcp::socket& socket()
  {
    return socket_;
  }

private:
  void handle_connect(const boost::system::error_code& error)
  {
    if (!error)
    {
      libgpp::byte_buffer buffer;

      boost::uint8_t number_of_pads = libgpp::utils::make_random(3) + 2;
      buffer.push_back_uint8(number_of_pads);

      while(number_of_pads--)
      {
        libgpp::byte_buffer padding = 
          libgpp::utils::rand_buffer(libgpp::utils::make_random(10) + 5);
        buffer.push_back_uint8(padding.size());
        buffer.push_back_data(padding);
      }

      buffer.print_output();

      write_packet(
        boost::bind(&erebus_client::handle_send_hello_packet, this),
        buffer
      );
    }
  }

  void handle_send_hello_packet()
  {
    boost::uint16_t nonce_length = read_buffer_.pop_front_uint16();
    libgpp::byte_buffer nonce = read_buffer_.pop_front_buffer(nonce_length);

    SHA_CTX sha_ctx;
    boost::uint8_t digest[20];

    SHA1_Init(&sha_ctx);
    SHA1_Update(&sha_ctx, &nonce[0], nonce_length);
    SHA1_Final(digest, &sha_ctx);

    RC4_set_key(&rc4_key_, 20, digest);
    is_encrypted_session_ = true;
  }

  void read_packet(const post_hook_handler_type& handler)
  {
    read_buffer_.resize(128);
    socket_.async_read_some(
      boost::asio::buffer(read_buffer_.v()),
      boost::bind(
        &erebus_client::handle_read_packet, this,
        boost::asio::placeholders::error,
        boost::asio::placeholders::bytes_transferred,
        handler
      )
    );

    /* set read timeout */
    read_timer_.expires_from_now(boost::posix_time::seconds(10));
    read_timer_.async_wait(
      boost::bind(
        &erebus_client::handle_read_timeout, 
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
    std::size_t bytes_transferred, const post_hook_handler_type& handler)
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
          RC4(&rc4_key_, bytes_transferred, &read_buffer_[0], &read_buffer_[0]);
        }

        boost::uint16_t packet_length = read_buffer_.pop_front_uint16();

        handler();
        return;
      }
      catch(const libgpp::error::basic_exception& e)
      {
        return_error = e.error_code();
      }
    }
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
        RC4(&rc4_key_, buffer.size(), &write_buffer_[0], &write_buffer_[0]);
      }

      boost::asio::async_write(
        socket_, 
        boost::asio::buffer(write_buffer_.v()),
        boost::asio::transfer_all(),
        boost::bind(
          &erebus_client::handle_write_packet, this,
          boost::asio::placeholders::error,
          boost::asio::placeholders::bytes_transferred,
          handler,
          is_read_handler_called
        )
      );
    }
    catch(const libgpp::error::basic_exception&)
    {
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
        read_buffer_.resize(1024);
        socket_.async_read_some(
          boost::asio::buffer(read_buffer_.v()),
          boost::bind(
            &erebus_client::handle_read_packet, this,
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
  }

private:
  boost::asio::io_service& io_service_;
  boost::asio::ip::tcp::socket socket_;
  boost::asio::deadline_timer read_timer_;

  libgpp::byte_buffer read_buffer_;
  libgpp::byte_buffer write_buffer_;

  RC4_KEY rc4_key_;
  
  bool is_encrypted_session_;
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
  for(int i=0; i<1000; i++)
  {
    try
    {
      boost::asio::io_service io_service;
      erebus_client client(io_service);

      client.run();
      io_service.run();   
    }
    catch(const std::exception&) 
    {
    }
  }

  return 0;
}
