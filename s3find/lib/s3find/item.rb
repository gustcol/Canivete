require 'action_view'
include ActionView::Helpers::NumberHelper

module S3find
  class Item
    attr_reader :key, :size, :modified, :etag

    def initialize(key: nil, size: nil, modified: nil, etag: nil)
      raise "Halt!!" if key.nil? 
      @key, @size, @modified, @etag = key, size.to_i, Time.parse(modified), etag
    end

    def filename
      @key.split('/')[-1]
    end
    
    def size_human
      number_to_human_size(@size)
    end

    def to_s
      [ 
        @modified.strftime('%F %T'), 
        size_human.rjust(9),
        @key
      ].join(' ')
    end

  end
end