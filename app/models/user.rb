class User < ApplicationRecord
  # Include default devise modules. Others available are:
  # :confirmable, :lockable, :timeoutable and :omniauthable
  devise :database_authenticatable, :registerable,
         :jwt_authenticatable, :validatable,
         jwt_revocation_strategy: JWTBlacklist

  attr_accessor :token

  def on_jwt_dispatch(token, payload)
    self.token = token
  end
end
