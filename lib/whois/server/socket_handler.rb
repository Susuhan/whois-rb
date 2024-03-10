# frozen_string_literal: true

#--
# Ruby Whois
#
# An intelligent pure Ruby WHOIS client and parser.
#
# Copyright (c) 2009-2022 Simone Carletti <weppos@weppos.net>
#++


require 'socket'
require 'whois/errors'


module Whois
  class Server

    # The SocketHandler is the default query handler provided with the
    # Whois library. It performs the WHOIS query using a synchronous
    # socket connection.
    class SocketHandler

      # Array of connection errors to rescue
      # and wrap into a {Whois::ConnectionError}
      RESCUABLE_CONNECTION_ERRORS = [
        SystemCallError,
        SocketError,
      ].freeze

      # Performs the Socket request.
      #
      # @todo *args might probably be a Hash.
      #
      # @param  [String] query
      # @param  [Array] args
      # @return [String]
      #
      def call(query, *args)
        execute(query, *args)
      rescue *RESCUABLE_CONNECTION_ERRORS => e
        raise ConnectionError, "#{e.class}: #{e.message}"
      end

      # Executes the low-level Socket connection.
      #
      # It opens the socket passing given +args+,
      # sends the +query+ and reads the response.
      #
      # @param  [String] query
      # @param  [Array] args
      # @return [String]
      #
      # @api private
      #
      def execute(query, *args)
        result = []

        client = TCPSocket.new(*args)
        client.write("#{query}\r\n")

        until client.eof? do
          result << client.gets
        end

        result.join('')
      rescue Errno::ECONNRESET
        result.join('')
      ensure
        client.close if client
      end
    end

  end
end
