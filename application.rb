#!/usr/bin/env ruby

require 'bundler/setup'
require 'sinatra'
require 'sinatra/flash'
require 'sinatra/reloader'
require 'warden'
require 'ruby-saml'
require 'dm-core'
require 'dm-types'
require 'dm-validations'
require 'dm-timestamps'
require 'dm-migrations'
require 'bcrypt'

# User model
class User
  include DataMapper::Resource
  include BCrypt
  property :id,            Serial
  property :auth_method,   String, :default => "password"
  property :user_name,     String, :required => true
  property :mail_addr,     String, :required => true
  property :password_hash, String, :length => 60
  property :name_id,       String

  def password
    @password ||= Password.new(password_hash)
  end

  def password=(pass)
    @password = Password.create(pass)
    self.password_hash = @password
  end

  def self.authenticate_with_password(user, pass)
    u = first(:user_name => user)
    if u.nil?
      puts "user is not found!"
      nil
    else
      if u.password == pass
        u
      else
        puts "invalid password!"
        nil
      end
    end
  end
end

# Initialize DM
DataMapper::Logger.new($stderr, :debug)
DataMapper.setup(:default, 'sqlite::memory:')
DataMapper.auto_migrate!

# Enable session
use Rack::Session::Pool, :expire_after => 900

# Configure warden
Warden::Strategies.add(:password) do
  def valid?
    params["username"] || params["password"]
  end

  def authenticate!
    u = User.authenticate_with_password(params["username"], params["password"])
    u.nil? ? fail!("Invalid user name or password") : success!(u)
  end
end

use Warden::Manager do |manager|
  manager.default_strategies :password
  manager.failure_app = Sinatra::Application
end

# Routes
get '/' do
  haml :index
end

get '/login' do
  haml :login
end

post '/login' do
  env['warden'].authenticate!
  # If authentication is succeeded, user will be redirected to index.
  redirect '/'
end

# Authentication is failed.
post '/unauthenticated' do
  haml :unauth
end

get '/login/consume' do
end

get '/logout' do
  env['warden'].logout
  redirect '/'
end

get '/logout/response' do
end

## Show sign-up page for password strategy.
get '/signup' do
  if env['warden'].authenticated?
    redirect '/'
  end
  haml :signup
end

## Create user account
post '/signup' do
  errors = []

  if !User.first(:user_name => params[:user][:user_name]).nil?
    errors << "User #{params[:user][:user_name]} is already existed."
  else
    u = User.new
    u.user_name = params[:user][:user_name]
    u.mail_addr = params[:user][:mail_addr]
    u.password  = params[:user][:password]
    unless u.save
      u.errors.each do |e|
        errors << e
      end
    end
  end

  if errors.size == 0
    flash[:info] = u.user_name
    redirect '/welcome'
  else
    flash[:notice] = "Creating account is Failed: #{errors.join(',')}"
    redirect '/signup'
  end
end

get '/welcome' do
  haml :welcome
end


