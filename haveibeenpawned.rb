require 'net/http'
require 'json'
require 'uri'
require 'digest'

require './environment.rb'

$api_key = ENV['API_KEY']

# List breaches
# A "breach" is an instance of a system having been compromised by an attacker and the data disclosed. 
# For example, Adobe was a breach, Gawker was a breach etc. 
# It is possible to return the details of each of breach in the system.
# Ex. ?domain=adobe.com
def breaches(domain="")
    return get_resource('https://haveibeenpwned.com/api/v3/breaches',{:domain => ""})
end

# Single breach
def single_breach(name="Adobe")
    return get_resource('https://haveibeenpwned.com/api/v3/breach/'.concat(name))
end

# Data classes
# A "data class" is an attribute of a record compromised in a breach. 
# For example, many breaches expose data classes such as "Email addresses" and "Passwords". 
# The values returned by this service are ordered alphabetically in a string array 
# and will expand over time as new breaches expose previously unseen classes of data.
def data_classes()
    return get_resource('https://haveibeenpwned.com/api/v3/dataclasses')
end

# Getting all pastes for an account
# The API takes a single parameter which is the email address to be searched for. 
# The email is not case sensitive and will be trimmed of leading or trailing white spaces. 
# The email should always be URL encoded. This is an authenticated API and an HIBP API key must be passed with the request.
def all_pastes(email,api_key)
    return get_resource_protected('https://haveibeenpwned.com/api/v3/pasteaccount/'.concat(email),api_key)
end

# Getting all breaches for an account
# The most common use of the API is to return a list of all breaches a particular account has been involved in. 
# The API takes a single parameter which is the account to be searched for. 
# The account is not case sensitive and will be trimmed of leading or trailing white spaces. 
# The account should always be URL encoded. This is an authenticated API and an HIBP API key must be passed with the request.
def all_breaches(email,api_key)
    return get_resource_protected('https://haveibeenpwned.com/api/v3/breachedaccount/'.concat(email),api_key)
end

# TODO: Add Add-Padding header for further security.
# Pwned Passwords overview
# Pwned Passwords are more than half a billion passwords which have previously been exposed in data breaches. 
# The service is detailed in the launch blog post then further expanded on with the release of version 2. 
# The entire data set is both downloadable and searchable online via the Pwned Passwords page. 
# Each password is stored as a SHA-1 hash of a UTF-8 encoded password. 
# The downloadable source data delimits the full SHA-1 hash and the password count with a colon (:) and each line with a CRLF.
# Ex. password_check(get_sha1('password')[0...5])
def password_check(hash)
    return get_resource('https://api.pwnedpasswords.com/range/'.concat(hash))
end

# Helper function
def get_resource(uri,params=nil)
    uri = URI(uri)
    params = params
    if params
        uri.query = URI.encode_www_form(params)
        res = Net::HTTP.get_response(uri)
    else
        res = Net::HTTP.get_response(uri)
    end
    return res.body if res.is_a?(Net::HTTPSuccess)
end

def get_resource_protected(uri,api_key, params=nil)
    uri = URI.parse(uri)
    http = Net::HTTP.new(uri.host, uri.port)
    http.use_ssl = true

    request = Net::HTTP::Get.new(uri.request_uri)
    request["hibp-api-key"] = api_key

    return http.request(request).body
end

def get_sha1(password)
    Digest::SHA1.hexdigest password
end