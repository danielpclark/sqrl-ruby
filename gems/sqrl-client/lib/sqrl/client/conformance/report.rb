# frozen_string_literal: true

module SQRL
  module Client
    module Conformance
      # The outcome of one conformance case.
      Case = Struct.new(:name, :group, :status, :message, :duration, :transcript, :error, keyword_init: true) do
        def passed? = status == :passed
        def failed? = status == :failed
        def skipped? = status == :skipped

        # @return [Hash] the values as a plain Hash
        def to_h
          { name: name, group: group, status: status, message: message, duration: duration&.round(3) }
        end

        # @return [String] one line per case
        def to_s
          mark = { passed: "PASS", failed: "FAIL", skipped: "SKIP" }[status]
          line = "#{mark}  #{group}/#{name}"
          line += "  (#{duration.round(2)}s)" if duration
          line += "\n      #{message}" if message && !passed?
          line
        end
      end

      # Every case of a run.
      class Report
        attr_reader :cases, :login_url, :started_at, :finished_at

        def initialize(login_url:)
          @login_url = login_url
          @cases = []
          @started_at = Time.now
          @finished_at = nil
        end

        # Record a finished case.
        # @api private
        def <<(kase)
          @cases << kase
          self
        end

        # Mark the run complete and record its duration.
        # @api private
        def finish!
          @finished_at = Time.now
          self
        end

        # @return [Array<Case>] cases that passed
        def passed = @cases.select(&:passed?)
        # @return [Array<Case>] cases that failed
        def failed = @cases.select(&:failed?)
        # @return [Array<Case>] cases that were skipped
        def skipped = @cases.select(&:skipped?)

        # True when nothing failed (skips do not count against the server).
        def passed? = failed.empty?

        # @return [Float, nil] seconds the run took
        def duration = ((@finished_at || Time.now) - @started_at)

        # @return [String] one-line totals
        def summary
          "#{passed.size} passed, #{failed.size} failed, #{skipped.size} skipped in #{duration.round(1)}s"
        end

        # @return [String] one line per case
        def to_s
          lines = ["SQRL conformance: #{@login_url}"]
          lines.concat(@cases.map(&:to_s))
          lines << summary
          lines.join("\n")
        end

        # @return [Hash] the values as a plain Hash
        def to_h
          { login_url: @login_url, summary: summary, passed: passed?, cases: @cases.map(&:to_h) }
        end

        # JUnit XML, for CI dashboards.
        def to_junit_xml
          esc = ->(s) { s.to_s.gsub("&", "&amp;").gsub("<", "&lt;").gsub(">", "&gt;").gsub('"', "&quot;") }
          out = +%(<?xml version="1.0" encoding="UTF-8"?>\n)
          out << %(<testsuite name="sqrl-conformance" tests="#{@cases.size}" failures="#{failed.size}" ) \
                 "skipped=\"#{skipped.size}\" time=\"#{duration.round(3)}\">\n"
          @cases.each do |c|
            out << %(  <testcase classname="#{esc.call(c.group)}" name="#{esc.call(c.name)}" time="#{(c.duration || 0).round(3)}">)
            out << %(<failure message="#{esc.call(c.message)}"/>) if c.failed?
            out << %(<skipped message="#{esc.call(c.message)}"/>) if c.skipped?
            out << "</testcase>\n"
          end
          out << "</testsuite>\n"
        end
      end
    end
  end
end
