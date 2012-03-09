#!/usr/bin/env ruby

require 'rubygems'
require 'bundler/setup'
require 'rake'
require 'yaml'
require 'ruby-saml'

desc "Create SAML SP Metadata from saml.yml"
task :create_metadata do
  settings = Onelogin::Saml::Settings.new
  config = YAML.load_file "./saml.yml"

  config.each do |k, v|
    settings.__send__ "#{k}=", v
  end
  metadata = Onelogin::Saml::Metadata.new.generate(settings)
  open("metadata.xml", 'w') do |f|
    f.puts metadata
  end
end

