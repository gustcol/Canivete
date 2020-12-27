require 'optparse'

module S3find
  class Application

    def run
        options = {}
        opt = OptionParser.new
        opt.banner = ""
        opt.separator "s3find - a find for S3 public buckets."
        opt.separator ""
        opt.separator "Usage:"
        opt.separator " s3find <bucket> [OPTIONS]"
        opt.separator ""
        opt.separator "   <bucket>   bucket_name or full URI ( http://bucket_name.s3.amazonaws.com )"
        opt.separator ""
        opt.separator "Options:"
        opt.on('-n', '--name=pattern'   , 'filters names by pattern') { |pattern| options[:name] = pattern }
        opt.on('-i', '--iname=pattern'  , 'case insensitive -n') { |pattern| options[:iname] = pattern }
        opt.on('-s', '--sort=field'     , 'sort by name | size | date') do |field| 
          abort("Invalid field for sort: #{field}. Should be one of  name | size | date.") unless %w(name size date).include? field
          options[:sort] = {name: :key, size: :size, date: :modified}[field.to_sym] 
        end
        opt.on('-r', '--rsort=field'    , 'reverse sort (descending)') do |field| 
          abort("Invalid field for sort: #{field}. Should be one of  name | size | date.") unless %w(name size date).include? field
          options[:sort] = {name: :key, size: :size, date: :modified}[field.to_sym]
          options[:reverse] = true
        end
        opt.on('-l', '--limit=num'  , 'limits items to display') { |num| options[:limit] = num.to_i }
        opt.on('-c', '--count'      , 'counts found items') { options[:count] = true }
        opt.on(nil,  '--download'   , 'downloads found items') { options[:download] = true }
        opt.separator ""
        opt.on('-h', '--help'       , 'displays help') { die(opt) }
        opt.on('-v', '--version'    , 'displays version') { die(S3find::VERSION) }
        opt.on(nil , '--verbose'    , 'displays extra info') { options[:verbose] = true }
        opt.separator ""
        
        begin
          opt.parse!
        rescue OptionParser::InvalidOption, OptionParser::MissingArgument 
          abort "#{$!.to_s.capitalize}\n"                                                           
        end 

        die(opt) if ARGV.empty?

        verbose  = options[:verbose]
        resource = ARGV[0] 
        debug(verbose, "Opening [#{resource}]")
        debug(verbose, "Options #{options}")
        
        s3 = Base.new(resource)
        debug(verbose, "Bucket Name = #{s3.bucket_name}")
        debug(verbose, "Bucket URI  = #{s3.bucket_uri}")
        
        result = s3.find(options)
        debug(verbose, "Found #{result.count} of #{s3.items.count} items")

        if options[:download]
          result.each do |item|
            if item.size > 0
              puts "downloading #{item.key} (#{item.size_human})"
              s3.download(item)
            else
              puts "skipping    #{item.key}"
            end
          end
        else
          result.each{ |item|  puts item.to_s }
        end

        if options[:count]
          count = s3.count(result)
          puts format("%s dirs, %s files, %s", count[:dirs], count[:files], number_to_human_size(count[:bytes]) ) 
        end

    end

    private 
    def die(message)
      puts message; exit
    end

    def debug(condition, message)
      puts "> #{message}" if condition
    end
  
  end 
end
