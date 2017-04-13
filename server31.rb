require 'sinatra'
require_relative 'util'

def insecure_compare(s1, s2)
    j = 0
    s1.split("").each do |i|
	if i != s2[j]
	    return false
	end
	j += 1
	sleep 0.005
    end
    return true
end

get '/test' do
  # http://localhost:4567/test?file=foo&signature=46b4ec586117154dacd49d664e5d63fdc88efb51
  file = params['file']
  signature = params['signature']
  #puts file
  #puts signature
  hmac = Util.hmac("key", file) 
  isOk = insecure_compare(hmac, signature)
  if isOk
    status 200
    body 'ok'
  else
    status 500
    body 'error'
  end
end








