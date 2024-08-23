package service.vaxapp;

import java.util.Optional;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;
import org.springframework.web.context.annotation.SessionScope;

import service.vaxapp.model.User;
import service.vaxapp.repository.UserRepository;

@Component
@SessionScope
public class UserSession {
	private Integer userId;

	@Autowired
	private UserRepository userRepository;

	public UserSession() {
		this.userId = null;
	}

	public User getUser() {
		if (!isLoggedIn())
			return null;

		Optional<User> user = userRepository.findById(userId);
		if (!user.isPresent())
			return null;

		return user.get();
	}
	
	public Boolean isLoggedIn() {
		return userId != null;
	}

	public Integer getUserId() {
		return userId;
	}

	public void setUserId(Integer userId) {
		this.userId = userId;
	}
}