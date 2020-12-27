# coding: utf-8
lib = File.expand_path('../lib', __FILE__)
$LOAD_PATH.unshift(lib) unless $LOAD_PATH.include?(lib)
require 's3find/version'

Gem::Specification.new do |spec|
  spec.name          = "s3find"
  spec.version       = S3find::VERSION
  spec.authors       = ["Andre Parmeggiani"]
  spec.email         = ["aaparmeggiani@gmail.com"]

  spec.summary       = "s3find public buckets"
  spec.description   = "A 'find' for S3 public buckets"
  spec.homepage      = "https://github.com/aaparmeggiani/s3find"
  spec.license       = "MIT"

  spec.files         = `git ls-files -z`.split("\x0")
  spec.executables   = spec.files.grep(%r{^bin/}) { |f| File.basename(f) }
  spec.test_files    = spec.files.grep(%r{^(test|spec|features)/})
  spec.require_paths = ["lib"]

  spec.add_development_dependency "bundler", "~> 1.14"
  spec.add_development_dependency "rake", "~> 12.0"
  spec.add_development_dependency "rspec", "~> 3.5"

  spec.add_dependency "activesupport", "~> 4.2"
  spec.add_dependency "actionview", "~> 4.2"
  spec.add_dependency "ruby-progressbar", "~> 1.8"

end
