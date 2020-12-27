require 'open-uri'
require 'active_support/core_ext/hash'

module S3find
  class Base
    attr_reader :bucket_name, :bucket_uri, :items

    def initialize(resource)
      @bucket_name = nil
      @bucket_uri  = nil
      @items = []
      fetch(resource)
    end

    def fetch(resource)
      doc = Hash.from_xml(open(endpoint(resource)))
      @bucket_name = doc['ListBucketResult']['Name']
      @bucket_uri  = bkt_uri(@bucket_name)
      contents = doc['ListBucketResult']['Contents']
      contents.each{ |c| @items << Item.new(
          key:      c['Key'],
          size:     c['Size'],
          modified: c['LastModified'],
          etag:     c['ETag'])
      }
    rescue
      puts "Error: #{$!}"
    end

    def find(options = {})
      return @items if @items.empty? || options.empty?
      r = @items
      r = r.select { |r| r.key.include?(options[:name]) } if options[:name]
      r = r.select { |r| r.key.downcase.include?(options[:iname]) } if options[:iname]
      r = r.sort_by{ |r| r.send(options[:sort])} if options[:sort]
      r = r.reverse if options[:reverse]
      r = r.first(options[:limit]) if options[:limit]
      r
    end

    def count(result=[])
      dirs = files = bytes = 0
      result.each do |r|
        dirs  += 1       if r.size == 0
        files += 1       if r.size > 0
        bytes += r.size  if r.size > 0
      end  
      { dirs: dirs, files: files, bytes: bytes }
    end

    def download(item)
      if item.size > 0
        pbar = SafeProgressBar.new(title: item.filename, total: nil, format: '%t: |%B| %p%% (%e )')   
        begin  
          open(@bucket_uri + item.key, 
              content_length_proc: ->(bytes) { pbar.total = bytes }, 
              progress_proc: ->(bytes) { pbar.progress = bytes }) do |io| 
            IO.copy_stream(io, "./#{item.filename}")
          end
        rescue Interrupt => e
          puts "\nAborted!" 
        end 
      end
    end

    private
 
    def endpoint(resource)
      return resource                     if resource.start_with? 'http'
      return resource.gsub('file://','')  if resource.start_with? 'file://'
      return bkt_uri(resource)
    end

    def bkt_uri(name)
      "http://#{name}.s3.amazonaws.com/"
    end

  end
end