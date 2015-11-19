class User < ActiveRecord::Base
	has_many :movies
	has_many :reviews, dependent: :destroy # This will delete reviews when a user is destroyed
	
	# Include default devise modules. Others available are:
	# :confirmable, :lockable, :timeoutable and :omniauthable
	devise :database_authenticatable, :registerable,
	     :recoverable, :rememberable, :trackable, :validatable
end
