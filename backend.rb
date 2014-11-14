#!/usr/bin/env ruby
# encoding: UTF-8

require 'yaml'
#require 'grit'
require 'rugged'
require 'pp'
require 'logger'
require 'time'
require 'timeout'
require 'socket'
require 'mail'
require 'uri'
require 'json'
require 'tempfile'
require 'net/http'
require 'net/ssh'
require 'net/http/digest_auth'

USERNAME=`whoami`.strip
PRIVATE_KEY_FILE = File.expand_path("~/.ssh/id_rsa")
PUBLIC_KEY_FILE = File.expand_path("~/.ssh/id_rsa.pub")

ROOT= File.dirname(File.expand_path __FILE__)
CONFIG_FILE= File.join ROOT, "config.yaml"
puts CONFIG_FILE


# quick fix to get correct string encoding
YAML::ENGINE.yamler='psych'
LOCAL_ENV=`uname`.strip.downcase
puts "LOCAL_ENV: #{LOCAL_ENV}"

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
	err_code = 0
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

		if status[1].exitstatus.to_s != 0
			err_code = status[1].exitstatus
		elsif   err_code =~ cmd_output.join(" ").match(/(\d+) FAILURE/)
			err_code = $1
		else
			err_code = 0
		end


		return {:timeout => false, :status => err_code, :output => cmd_output, :pid => pipe.pid}
	rescue Timeout::Error
		LOGGER.error "#{command} pid #{pipe.pid} timeout at #{Time.now}" rescue nil
		Process.kill 9, pipe.pid if pipe.pid rescue nil
		return {:timeout =>true, :status => 254, :output => cmd_output}
	end
end

def ssh_exec!(ssh, commands)
	stdout_data = ""
	#stderr_data = ""
	exit_code = nil
	exit_signal = nil
	ssh.open_channel do |channel|
		if String === commands
			command = commands
		else
			#XXX problematic for bash script
			# e.g. if..then
			command = commands.join(";")
		end
		channel.exec(command) do |ch, success|
			unless success
				abort "FAILED: couldn't execute command (ssh.channel.exec)"
			end
			channel.on_data do |ch,data|
				stdout_data+=data
			end

			channel.on_extended_data do |ch,type,data|
				stdout_data+=data
			end

			channel.on_request("exit-status") do |ch,data|
				exit_code = data.read_long
			end

			channel.on_request("exit-signal") do |ch, data|
				exit_signal = data.read_long
			end
		end
	end
	ssh.loop
	[stdout_data, exit_code, exit_signal]
end
	

def start_on_remote remote
	ssh = Net::SSH.start(remote[:host], remote[:ssh_username], :password => remote[:ssh_pass])
	yield ssh if block_given?
	ssh
end

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

	class TestPhraseBase
		attr_accessor :name, :timeout
		attr_reader :result
		def initialize(_name, _timeout)
			@name = _name
			@timeout = _timeout
		end
	end

	class TestPhrase < TestPhraseBase
		attr_accessor :cmd
		def initialize(_name, _cmd, _timeout=10)
			super _name, _timeout
			@cmd = _cmd
		end

		def run
			@result = time_cmd @cmd, @timeout
		end
	end

	class LocalTestPhrase < TestPhraseBase
		attr_accessor :cmds
		def initialize(_name, _phrase, _cmds, _timeout=10)
			super "LOCAL-#{_name}-#{_phrase}", _timeout
			@cmds = _cmds
			@cmds = [_cmds] if String === _cmds
		end

		def run
			bash = Tempfile.new('localtest')
			bash.write @cmds.join("\n")
			bash.close
			@result = time_cmd "/bin/bash #{bash.path}", @timeout
			bash.unlink
			@result
		end
	end

	class RemoteError < RuntimeError
		attr_accessor :code
		def initialize(msg=nil, code=nil)
			super msg
			@code = code
		end
	end



	class RemoteBuildPhrase < TestPhraseBase
		attr_accessor :config, :remote, :commitid, :refname, :reponame
		def initialize(_name, _phrase, _remote, _refname, _config, _cid, _cmds = [], _timeout = 30, need_checkout = false)
			super "REMOTE-#{_name}-#{_phrase}", _timeout
			@config = _config
			@commitid = _cid
			@refname = _refname
			@reponame = @config[:name]
			@remote = _remote
			@cmds = _cmds
			@cmds = [_cmds] if String === _cmds
			@need_checkout = need_checkout
		end
		def prepare_repo 
			LOGGER_VERBOSE.info "Prepare repo for #{@reponame} on #{@remote[:name]}"
			r = ssh_exec! @ssh, "mkdir -p #{@remote[:work_dir]}"
			#LOGGER_VERBOSE.info r.first
			raise RemoteError.new("fail to create work dir", r[1]) if r[1] != 0

			r = ssh_exec! @ssh, "cat #{@remote[:work_dir]}/#{@reponame}/.git/config"
			#puts r.first
			if r[1] != 0
				LOGGER.info "cloning #{@reponame} to #{@remote[:name]}"
				r = ssh_exec! @ssh, "cd #{@remote[:work_dir]} && git clone #{@config[:url]}"
				#LOGGER_VERBOSE.info r.first
				raise RemoteError.new("fail clone #{@reponame}: #{r[0]}", r[1]) if r[1] != 0
			end
			return "Prepare repo done"
		end

		def fetch_and_checkout
			LOGGER_VERBOSE.info "fetching repo #{@reponame} on #{@remote[:name]}, #{@refname} => #{@commitid}"
			fetch_ref = @refname
			#XXX origin/master can't be fetched
			fetch_ref = $1 if @refname =~ /origin\/(.+)/
			r = ssh_exec! @ssh, "cd #{remote[:work_dir]}/#{@reponame} && git fetch origin #{fetch_ref} && git checkout #{@commitid}" 
			throw RemoteError.new("fail to fetch #{@reponame}: #{r[0]}", r[1]) if r[1] != 0
			r = ssh_exec! @ssh, "cd #{remote[:work_dir]}/#{@reponame} && git submodule init && git submodule update" 
			throw RemoteError.new("fail to fetch submodule #{@reponame}: #{r[0]}", r[1]) if r[1] != 0
			r.first
		end

		def run_build_script
			cmds = ["cd #{@remote[:work_dir]}/#{@reponame}"] + @cmds
			#p cmds.join(";")
			LOGGER_VERBOSE.info "run script repo #{@reponame} on #{@remote[:name]}, #{@refname} => #{@commitid}"
			r = ssh_exec! @ssh, cmds
			#throw RemoteError.new("fail to fetch #{@reponame}: #{r[0]}", r[1]) if r[1] != 0
		end

		private :prepare_repo, :fetch_and_checkout, :run_build_script

		def run
			LOGGER.info "Running on #{@remote[:name]}: #{@reponame} => #{@name}"
			@ssh = start_on_remote @remote
			timeout = false
			result = []
			err_code = 0
			begin
				if @need_checkout
					result += prepare_repo.split("\n")
					result += fetch_and_checkout.split("\n")
				end
				r = run_build_script
				result += r[0].split("\n")
				err_code = r[1]
			rescue RemoteError => e
				timeout = false
				result += e.message.split("\n")
				err_code = e.code
			rescue Exception => e
				timeout = true
				err_code = 62 #ETIME
			end
			#puts result.join("\n")
			@ssh.close
			#fail "XXX"
			source_enc = @remote[:source_encoding]
			source_enc ||= "UTF-8"
			result.map!{|e| e.encode "UTF-8", source_enc, :invalid => :replace }
			@result = {:timeout=> timeout, :status => err_code, :output => result}
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
		b << YAML.dump(result[:gerrit_info]) << "\n\n" if result[:gerrit_info]
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

	def build_runner reponame, refname, commitid
		begin
			buildconfig = YAML::load(File.read('.autobuild.yml'))
		rescue
			LOGGER.error "Fail to parse .autobuild.yml for #{@name}"
			return nil
		end
		buildconfig["jobs"] ||= {}
		job_seq = ["script", "install", "test"]
		@runner = TestGroup.new
		buildconfig["jobs"].each {|k,v|
			next if v['env'] != LOCAL_ENV
			job_seq.each {|js|
				next unless v[js]
				@runner.push(TestGroup::LocalTestPhrase.new(k, js, v[js], @build_timeout_s))
			}
		}

		buildconfig["jobs"].each {|k,v|
			env = v['env']
			next if v['env'] == LOCAL_ENV
			unless $CONFIG[:remote_server][env]
				LOGGER.error "Remote server #{env} not available"
				next
			end
			job_seq.each {|js|
				next unless v[js]
				# only checkout at build phrase
				@runner.push(TestGroup::RemoteBuildPhrase.new k, js, $CONFIG[:remote_server][env], refname,
					     @config, commitid, v[js], @build_timeout_s, js == 'script')
			}
		}
		@runner
	end

	def run_test_for_commits(ref, target_commit, new_commits, info)

		commitid = target_commit.oid
		LOGGER.info "Repo #{@name}: OK, let's test branch #{ref.name}:#{commitid}"

		#now begin test

		# LOGGER_VERBOSE.info res.body
		remote_ref = info ? info[:remote_ref] : ref.name
		runner = build_runner @name, remote_ref, commitid rescue nil
		unless runner
			LOGGER.error "Fail to build jobs for #{@name}"
			return
		end
		failed, result = runner.run_all

		ok = failed ? "FAIL" : "OK"
		## we can use c.to_hash
		commits_info = new_commits.map {|c| c.simplify }

		report_name = File.join @result_dir, "#{commitid}-#{Time.now.to_i}-#{ok}-#{$$}.yaml"
		report = {:ref => [ref.name, commitid], :filter_commits => commits_info, :ok => ok, :result => result, :timestamp => Time.now.to_i, :gerrit_info => info }


		File.open(report_name, "w") do |io|
			## change enconding
			YAML.dump report, io
		end

		LOGGER.info "Repo #{@name}: Test done"


		gerrit_verify_change info, !failed if info
		send_mail ref, target_commit, report, report_name

	end

	def white_black_list(refname)
		return @whitelist.any? {|r| refname =~ r} unless @whitelist.empty?
		!(@blacklist.any?{|r| refname =~ r})
	end

	def gerrit_do_req(url)
		#`curl -s --digest --user '#{@config[:gerrit_user]}:#{@config[:gerrit_pass]}' #{@config[:gerrit_url]}/a#{url}`
		digest_auth = Net::HTTP::DigestAuth.new

		uri = URI.parse "#{@config[:gerrit_url]}/a#{url}"
		h = Net::HTTP.new uri.host, uri.port

		uri.user = @config[:gerrit_user]
		uri.password = @config[:gerrit_pass]

		req = Net::HTTP::Get.new uri.request_uri
		res = h.request req
		auth = digest_auth.auth_header uri, res['www-authenticate'], 'GET'
		req = Net::HTTP::Get.new uri.request_uri
		req.add_field 'Authorization', auth

		h.request(req).body.split("\n")[1..-1].join("\n")
	end
	def gerrit_post_req(url, body)
		#`curl -s --digest --user '#{@config[:gerrit_user]}:#{@config[:gerrit_pass]}' #{@config[:gerrit_url]}/a#{url}`
		digest_auth = Net::HTTP::DigestAuth.new

		uri = URI.parse "#{@config[:gerrit_url]}/a#{url}"
		h = Net::HTTP.new uri.host, uri.port

		uri.user = @config[:gerrit_user]
		uri.password = @config[:gerrit_pass]

		req = Net::HTTP::Post.new uri.request_uri
		res = h.request req
		auth = digest_auth.auth_header uri, res['www-authenticate'], 'POST'
		req = Net::HTTP::Post.new uri.request_uri
		req.add_field 'Authorization', auth
		req.add_field 'Content-Type', 'application/json'
		req.body = body
		h.request(req).body.split("\n")[1..-1].join("\n")
	end


	def gerrit_list_open
		LOGGER.info "connect to gerrit: #{@name}"
		return [] unless @config[:gerrit_url]
		t = gerrit_do_req("/changes/?q=status:open&o=CURRENT_REVISION")

		changes = JSON.parse(t) rescue []
		list = []
		changes.select{|c| c["project"] == @name}.each {|c|
			rev = c["current_revision"]
			ref = c["revisions"][rev]["fetch"]["http"]["ref"]
			c[:remote_ref] = ref
			c[:rev] = rev
			#ref = c["_number"]
			branch = "origin/" + c["branch"]
			list << {:rev => rev, :remote_ref => ref, :branch_name => branch, :gerrit_info => c}
		}
		origin = @repo.remotes.first
		#new_branchs = []
		list.each {|e|
			origin.fetch [e[:remote_ref]], :credentials => $DEFAULT_CRED
			LOGGER_VERBOSE.info e[:remote_ref]

			#$CONFIG[:remote_server].each {|k, ser|
			#	uri = URI.parse(ser)
			#	params = {'ref'=>"#{e[:remote_ref]}"}
			#	resp = Net::HTTP.post_form(uri,params)
			#}

			#p @repo.lookup(e[:rev])
			e[:commit] = @repo.lookup(e[:rev])
			e[:branch] = @repo.branches[e[:branch_name]]
		}
		list
		#new_branchs
	end

	def gerrit_verify_change gerrit_info, result
		url = "/changes/#{gerrit_info["id"]}/revisions/#{gerrit_info["current_revision"]}/review"
		body = {
			"message" => "autobuild",
			"labels" => {
				"Verified" => (result ? 1 : -1)
			}
		}.to_json

		resp = gerrit_post_req url, body
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

		#:commit and :branch must NOT be null
		list_open = gerrit_list_open rescue []
		#list_open = []
		#upstream branches
		@repo.branches.each(:remote) {|r|
			list_open << {:branch => r, :commit => r.target, :is_upstream => true}
			LOGGER_VERBOSE.info "#{r.name} => #{r.target.oid}"
		}
		#p list_open
		#
		

		list_open.each do |lo|
			ref = lo[:branch]
			commit = lo[:commit]
			next if ref.name =~ /.+\/HEAD/
			#next if @blacklist.include? ref.name
			next unless white_black_list ref.name

			commitid = commit.oid
			#p ref.target_id
			if compiled_list.include? commitid
				#LOGGER.info "Mark upstream: #{ref.name} => #{commitid}"
				last_test_list[ref.name] = commitid if lo[:is_upstream]
				next
			end

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
				run_test_for_commits ref, commit, new_commits, lo[:gerrit_info]
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

def check_remotes
	$CONFIG[:remote_server].each {|k,v|
		LOGGER.info "Checking remote: #{k}..."
		v[:name] = k
		begin
			Timeout.timeout(20) do 
				start_on_remote(v) do |ssh|
					res = ssh.exec!("hostname")
					LOGGER.info "hostname: #{res}"
				end
			end
		rescue Timeout::Error
			INFO.fatal "Timeout: remote server #{k}"
		end
	}
end

def startme

	trap "SIGINT" do
		LOGGER.error "SIGINT recerved, Exit."
		exit 130
	end

	old_config_md5 = nil
	repos = Hash.new
	loop do
		config_md5 = md5sum CONFIG_FILE
		if config_md5 != old_config_md5
			puts "============================"
			puts "Loading config..."
			puts "============================"
			$CONFIG = YAML.load File.read(CONFIG_FILE)
			$CONFIG[:remote_server] ||= {}
			check_remotes

			$DEFAULT_CRED = Rugged::Credentials::SshKey.new(:privatekey=>PRIVATE_KEY_FILE,
									:publickey=>PUBLIC_KEY_FILE, :username=>$CONFIG[:git_username])
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
			sleep 5 #sleep a little while per repo
		end
		sleep ($CONFIG[:sleep] || 30)
		LOGGER.ping
	end
end

if __FILE__ == $0
	startme
end

