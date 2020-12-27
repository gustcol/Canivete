## s3find

A 'find' for S3 public buckets.

## Installation

Add this line to your application's Gemfile:

```ruby
gem 's3find'
```

And then execute:

```
$ bundle
```

Or install it yourself:

```
$ gem install s3find
```

## Usage

### IRB or inside your code:

```
require 's3find''

s3 = S3find::Base.new('publicdata.landregistry.gov.uk')
result = s3.find(limit: 10)
````

With the gem installed, ```s3find_console``` will start IRB with s3find loaded.


### Command line wrapper:

```
$ s3find -h

s3find - a find for S3 public buckets.

Usage:
 s3find <bucket> [OPTIONS]

   <bucket>   bucket_name or full URI ( http://bucket_name.s3.amazonaws.com )

Options:
    -n, --name=pattern               filters names by pattern
    -i, --iname=pattern              case insensitive -n
    -s, --sort=field                 sort by name | size | date
    -r, --rsort=field                reverse sort (descending)
    -l, --limit=num                  limits items to display
    -c, --count                      counts found items
        --download                   downloads found items

    -h, --help                       displays help
    -v, --version                    displays version
        --verbose                    displays extra info
```

Examples:

```
$ s3find publicdata.landregistry.gov.uk --limit=5 --count
2016-03-03 19:31:20   0 Bytes market-trend-data/
2016-03-03 19:42:07   0 Bytes market-trend-data/additional-price-paid-data/
2016-03-03 19:32:34   0 Bytes market-trend-data/house-price-index-data/
2016-04-28 08:30:40    111 KB market-trend-data/house-price-index-data/Annual-Change.csv
2016-04-28 08:30:40   2.02 MB market-trend-data/house-price-index-data/Average-Prices-SA-SM.csv
3 dirs, 2 files, 2.13 MB

$ s3find http://publicdata.landregistry.gov.uk.s3.amazonaws.com --iname=change -rname --count
2016-04-28 08:30:45    112 KB market-trend-data/house-price-index-data/Monthly-Change.csv
2016-04-28 08:30:40    111 KB market-trend-data/house-price-index-data/Annual-Change.csv
0 dirs, 2 files, 223 KB
```

## Contributing

Bug reports and pull requests are welcome through this repo.

## License

MIT