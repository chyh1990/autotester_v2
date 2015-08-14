#!/usr/bin/env ruby

fail 'no input file' unless ARGV[0]

if File.stat(ARGV[0]).size > 1 * 1024 * 1024
  $stderr.puts "#{ARGV[0]} too large, skipping..."
  exit
end

lineno = 1
fn = File.basename(ARGV[0])
errors = 0

R1 = Regexp.new '\r\n$'
R2 = Regexp.new '\s+\n$'
IO.foreach ARGV[0] do |line|
  if !line.valid_encoding?
    puts "#{fn}:#{lineno}:\tInvalid UTF-8 encoding"
  elsif line =~ R1
    puts "#{fn}:#{lineno}:\tDOS line ending (CRLF) found, use Unix line ending (LF) instead"
    errors += 1
  elsif line =~ R2
    puts "#{fn}:#{lineno}:\tTrailing whitespace found"
    errors += 1
  end
  lineno += 1
end

exit 1 if errors > 0
