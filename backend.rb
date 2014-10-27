#!/usr/bin/env ruby
# encoding: utf-8

require 'yaml'
#require 'grit'
require 'rugged'
require 'pp'
require 'logger'
require 'time'
require 'timeout'
require 'socket'
require 'mail'
require 'json'

USERNAME=`whoami`.strip

ROOT= File.dirname(File.expand_path __FILE__)
CONFIG_FILE= File.join ROOT, "config.yaml"
puts CONFIG_FILE


# quick fix to get correct string encoding
YAML::ENGINE.yamler='syck'

$CONFIG = Hash.new

class Numeric
  def datetime_duration
    secs  = self.to_int
    mins  = secs / 60
    hours = mins / 60
    days  = hours / 24

    if days > 0
      "#{days} days and #{hours % 24} hours"
    elsif hours > 0
      "#{hours} hours and #{mins % 60} minutes"
    elsif mins > 0
      "#{mins} minutes and #{secs % 60} seconds"
    elsif secs >= 0
      "#{secs} seconds"
    end
  end
end

class PingLogger < Logger
	attr_reader :lastping
	def initialize(io, len = 20)
		super io
		@buffer = Array.new
		@lastping = Time.new
		@len = len
		@server = nil

		info "Hello from Tester backend!"
		info "Start now..."
	end

	def newline(line)
		@buffer.shift if @buffer.count >= @len
		@buffer << line
		ping
	end

	def ping
		@lastping = Time.now
	end

	def info t
		newline "INFO #{Time.now} #{t}"
		super t
	end

	def error t
		newline "ERROR #{Time.now} #{t}"
		super t
	end

	def fatal t
		newline "FATAL #{Time.now} #{t}"
		super t
	end

	def server_loop addr, port
		return if @server
		puts "Logger server start @ #{port}"
		@server = TCPServer.new(addr, port)
		loop do
			begin
				client = @server.accept
				client.puts "Last ping: #{@lastping} (#{(Time.now-@lastping).datetime_duration} ago)"
				@buffer.each { |l| client.puts l}
				client.close
			rescue StandardError => e
				puts "TCPServer error: #{e.message}"
				next
			end
		end
	end

end


LOGGER_VERBOSE = Logger.new STDERR
LOGGER = PingLogger.new STDOUT

def md5sum fn
	md5 = `md5sum #{fn}`
	fail if $?.exitstatus != 0
	md5
end

def error info
	LOGGER.error info
end

def time_cmd(command,timeout)
	cmd_output = []
	LOGGER.info "Entering #{command} at #{Time.now}"
	begin
		pipe = IO.popen("#{command} 2>&1")
	rescue Exception => e
		LOGGER.error "#{command} failed"
		return {:timeout =>false, :status => 255, :output=> [e.to_s]}
    	end

	begin
		status = Timeout.timeout(timeout) do
			#puts "pid: #{$$}"
			pipe.each_line {|g| cmd_output << g.chomp }
			#return [child pid, status]
			Process.waitpid2(pipe.pid)
		end
		return {:timeout =>false, :status =>status[1].exitstatus, :output => cmd_output, :pid => pipe.pid}
	rescue Timeout::Error
		LOGGER.error "#{command} pid #{pipe.pid} timeout at #{Time.now}" rescue nil
		Process.kill 9, pipe.pid if pipe.pid rescue nil
		return {:timeout =>true, :status => 254, :output => cmd_output}
	end
end

#class Grit::Actor
#	def simplify
#		"#{@name} <#{@email}>"
#	end
#end
#

class Rugged::Commit
	def simplify_actor actor
		"#{actor[:name]} <#{actor[:email]}>"
	end
	def simplify
		{:id => oid,
   		 :author => simplify_actor(author),
		 :committer => simplify_actor(committer), 
		 :committed_date => time.to_s,
		 :message => message.split("\n").first
		}
	end
end

class CommitFilter
	class << self
		def method_missing(name, *args)
			LOGGER.error "filter not found #{name}"
			args.first
		end

		def ext(extlist, commits)
			commits.select do |c|
				# f => ["test.c", 1, 0 ,1]
				change_files = []
				c.diff.each_patch {|p| change_files << p.delta.new_file[:path]}
				(c.parents.count > 1)  \
				  || (change_files.any? { |f| extlist.include? File.extname(f.first) })
			end
		end
	end
end

class TestGroup
	attr_reader :phrases, :result
	def initialize
		@phrases = Array.new
		@result = Array.new
	end

	def push(phrase)
		@phrases << phrase
	end

	def run_all
		@result = Array.new
		failed = false
		@phrases.each do |p|
			LOGGER.info "Running #{p.name}"
			st = Time.now
			#run it
			res = p.run
			time = Time.now - st
			@result << {:name => p.name, :time => time, :result => res}
			## IMPORTANT
			if res[:status] != 0
				failed = true
				break
			end
		end
		[failed, @result]
	end

	class TestPhrase
		attr_accessor :name, :cmd, :timeout
		attr_reader :result
		def initialize(_name, _cmd, _timeout=10)
			@name = _name
			@cmd = _cmd
			@timeout = _timeout
		end

		def run
			@result = time_cmd @cmd, @timeout
		end
	end

end

class CompileRepo
	attr_reader :repo, :name, :url, :blacklist

	def initialize config

		@config = config
		@name = config[:name]
		fail "REPO name is null" if @name.nil?
		@url = config[:url]
		@nomail = config[:nomail]
		@mode = config[:mode] || :normal

		@blacklist = config[:blacklist] || []
		#@blacklist.map! {|e| "origin/" + e}
		@blacklist.map! {|e| /#{e}/}
		@whitelist = config[:whitelist] || []
		@whitelist.map! {|e| /#{e}/}

		@build_timeout_s = (config[:build_timeout_min] || 1) * 60
		@run_timeout_s = (config[:run_timeout_min] || 1) * 60
		@filters = config[:filters] || []
		@result_dir = File.join $CONFIG[:result_abspath], @name

		@runner = TestGroup.new
		@runner.push(TestGroup::TestPhrase.new "AutoBuild", './autobuild.sh', @build_timeout_s)
		@runner.push(TestGroup::TestPhrase.new "AutoTest", './autotest.sh ' + @result_dir, @run_timeout_s)

		begin
			@repo = Rugged::Repository.new config[:name]
		rescue Rugged::OSError => e
			LOGGER.info  "Cloning #{@name}"
			#`git clone "#{@url}" "#{@name}"`
			#fail "Fail to clone #{@url}" if $?.exitstatus != 0
			#@repo = Grit::Repo.new config[:name]
			Rugged::Repository.clone_at @url, @name, :credentials => $DEFAULT_CRED
			@repo = Rugged::Repository.new config[:name]
		end
		LOGGER.info "Repo #{@name} ready!"
		#@repo.remotes.each { |r| puts "  #{r.name} #{r.commit.id}" }
		@repo.branches.each_name(:remote).sort.each{|r| puts "  #{r}"}
	end

	def send_mail(ref, target_commit, result, report_file = nil)
		return if $CONFIG[:mail].nil?
		return if @nomail
		commit = target_commit
		author = commit.author
		LOGGER_VERBOSE.info "send_mail to #{author[:email]}"
		conf = $CONFIG[:mail]
		dm = $CONFIG[:domain_name] || "localhost"
		b = []
		b << "Hi, #{author[:name]}:"
		b << "Here is a report from autotest system, please visit: http://#{dm}"
		b << "#{Time.now}"
		b << "===================================\n"
		b << "ENVIRONMENT"
		env = File.read(File.join(ROOT, "env.txt")) rescue "Unknown"
		b << env
		b << "===================================\n"
		b << ">>> git clone #{@url}"
		b << YAML.dump(result[:ref])
		b << YAML.dump(result[:filter_commits]) << "\n"
		b << "===================================\n"
		result[:result].each do |r|
			b << "#{r[:name]}    #{r[:result][:status]}"
			b << "Time: #{r[:time]}"
			b << "---"
			r[:result][:output].each {|l| b << l }
			b << "===================================\n"
		end
		b << "\nFrom Git autotest system"
		repo_name = @name

		mail = Mail.new do
			from conf[:from]
			to   author[:email]
			cc   conf[:cc] || []
			subject "[Autotest][#{result[:ok]}] #{repo_name}:#{ref.name} #{target_commit.oid}"
			body b.join("\n")
			add_file report_file if report_file
		end
		mail.deliver! rescue LOGGER.error "Fail to send mail to #{author[:email]}"
	end

	def run_test_for_commits(ref, target_commit, new_commits)

		commitid = target_commit.oid
		LOGGER.info "Repo #{@name}: OK, let's test branch #{ref.name}:#{commitid}"

		#now begin test
		failed, result = @runner.run_all
		ok = failed ? "FAIL" : "OK"
		## we can use c.to_hash
		commits_info = new_commits.map {|c| c.simplify }

		report_name = File.join @result_dir, "#{commitid}-#{Time.now.to_i}-#{ok}-#{$$}.yaml"
		report = {:ref => [ref.name, commitid], :filter_commits => commits_info, :ok => ok, :result => result, :timestamp => Time.now.to_i }

		File.open(report_name, "w") do |io|
			YAML.dump report, io
		end

		LOGGER.info "Repo #{@name}: Test done"

		send_mail ref, target_commit, report, report_name

	end

	def white_black_list(refname)
		return @whitelist.any? {|r| refname =~ r} unless @whitelist.empty?
		!(@blacklist.any?{|r| refname =~ r})
	end

	def gerrit_list_open
		#LOGGER.info "connect gerrit #{@name}"
		return [] unless @config[:gerrit_url]
		#XXX use open-uri?
		t = `curl -s --digest --user '#{@config[:gerrit_user]}:#{@config[:gerrit_pass]}' #{@config[:gerrit_url]}/a/changes/?q=status:open\\&o=CURRENT_REVISION`.split("\n")[1..-1].join("\n")
		
		changes = JSON.parse(t) rescue []
		list = []
		changes.select{|c| c["project"] == @name}.each {|c|
			rev = c["current_revision"]
			ref = c["revisions"][rev]["fetch"]["http"]["ref"]
			branch = "origin/" + c["branch"]
			list << {:rev => rev, :remote_ref => ref, :branch_name => branch}
		}
		origin = @repo.remotes.first
		#new_branchs = []
		list.each {|e|
			origin.fetch [e[:remote_ref]], :credentials => $DEFAULT_CRED
			#new_branchs << @repo.branches.create(e[:branch_name], "FETCH_HEAD")
			#p @repo.lookup(e[:rev])
			e[:commit] = @repo.lookup(e[:rev])
			e[:branch] = @repo.branches[e[:branch_name]]
		}
		list
		#new_branchs
	end

	def start_test
		#we are in repo dir
		origin = @repo.remotes.first
		return unless origin

		begin
			LOGGER_VERBOSE.info "fetching #{@name}"
			#@repo.remote_fetch origin
			origin.fetch :credentials => $DEFAULT_CRED
		rescue Exception => e
			LOGGER.error "Failed to fetch #{@name}, #{e.inspect}"
			return
		end


		last_test_file = File.join @result_dir, ".list"
		compiled_file = File.join @result_dir, ".compiled"

		last_test_list = Hash[File.readlines(last_test_file).map {|line| line.chomp.split(/\s/,2)}] rescue Hash.new
		compiled_list = File.readlines(compiled_file).map{|line| line.chomp} rescue []

		new_compiled_list = []

		list_open = gerrit_list_open
		@repo.branches.each(:remote) {|r|
			list_open << {:branch => r, :commit => r.target, :is_upstream => true}
		}
		#p list_open

		list_open.each do |lo|
			ref = lo[:branch]
			commit = lo[:commit]
			next if ref.name =~ /.+\/HEAD/
			#next if @blacklist.include? ref.name
			next unless white_black_list ref.name

			commitid = commit.oid
			#p ref.target_id
			next if compiled_list.include? commitid


			begin
				#force checkout here
				LOGGER.info "Checkout #{@name} #{ref.name}:#{commitid}"
				@repo.checkout(commitid, :strategy => :force)
			rescue
				error "Fail to checkout #{commitid}"
				next
			end

			## extract commit info, max item 10
			last_test_commit = last_test_list[ref.name]

			walker = Rugged::Walker.new @repo
			walker.sorting(Rugged::SORT_TOPO)
			new_commits = []
			walker.push(commitid)
			if last_test_commit
				#new_commits = @repo.commits_between(last_test_commit, commitid).reverse
				walker.hide(last_test_commit)
			else
				LOGGER.info "#{ref.name} new branch?"
			end
			walker.each {|oid|
				new_commits << oid
				break if new_commits.size > 30
			}
			# old..new
			new_commits.reverse!
			# if the branch has been reset after last test,
			# new_commits will be empty
			new_commits = [ref.target] if new_commits.empty?

			puts "#{@name} before filters:"
			new_commits.each {|c| puts "  #{c.oid}" }

			#apply filters
			@filters.each { |f| new_commits = CommitFilter.__send__(*f, new_commits) }

			puts "#{@name} after filters:"
			new_commits.each {|c| puts "  #{c.oid}" }

			LOGGER.info "too many commits, maybe new branch or rebased" if new_commits.length > 10

			if new_commits.empty?
				LOGGER.info "#{@name}:#{ref.name}:#{commitid} introduced no new commits after fiters, skip build"
			else
				run_test_for_commits ref, commit, new_commits
			end

			# mark it
			new_compiled_list |= [commitid]
			compiled_list << commitid
			last_test_list[ref.name] = commitid if lo[:is_upstream]
		end

		File.open(last_test_file, "w") do |f|
			last_test_list.each {|k,v| f.puts "#{k} #{v}"}
		end
		File.open(compiled_file, "a") do |f|
			new_compiled_list.each {|e| f.puts e}
		end
	end

end

def create_all_repo
	LOGGER.info "Create or checkout all repos"
	repos = Hash.new
	$CONFIG[:repos].each do |r|
		begin
			repos[ r[:name] ] = CompileRepo.new r
		rescue StandardError => e
			error "#{r[:name]} #{e} not available, skip"
			puts e.backtrace
			next
		end
		report_dir = File.join $CONFIG[:result_abspath], r[:name]
		unless File.directory? report_dir
			`mkdir #{report_dir}`
			#`mkdir #{File.join report_dir, 'compile'}`
			#`mkdir #{File.join report_dir, 'running'}`
		end
	end
	repos
end

def start_logger_server
	Thread.start do
		LOGGER.server_loop $CONFIG[:ping][:backend_addr], $CONFIG[:ping][:port]
	end
end

def startme
	old_config_md5 = nil
	repos = Hash.new
	loop do
		config_md5 = md5sum CONFIG_FILE
		if config_md5 != old_config_md5
			puts "============================"
			puts "Loading config..."
			puts "============================"
			$CONFIG = YAML.load File.read(CONFIG_FILE)

			$DEFAULT_CRED = Rugged::Credentials::SshKey.new(:privatekey=>"/home/#{USERNAME}/.ssh/id_rsa",
									:publickey=>"/home/#{USERNAME}/.ssh/id_rsa.pub", :username=>$CONFIG[:git_username])
			old_config_md5 = config_md5
			Dir.chdir $CONFIG[:repo_abspath]
			repos = create_all_repo
			#Grit::Git.git_timeout = $CONFIG[:git_timeout] || 10
			start_logger_server
		end
		repos.each do |k,v|
			#chdir first
			Dir.chdir File.join($CONFIG[:repo_abspath], k)
			v.start_test
			Dir.chdir $CONFIG[:repo_abspath]
		end
		sleep ($CONFIG[:sleep] || 30)
		LOGGER.ping
	end
end

if __FILE__ == $0
	startme
end

