package me.vinodh.sping_boot_sample.domain;

import java.util.Collection;
import java.util.List;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

public class CustomUserDetails implements UserDetails {

	/**
	 * 
	 */
	private static final long serialVersionUID = 1L;

	private String id;
	private String emailId;
	private String username;
	private String password;
	private List<GrantedAuthority> authorities;

	public CustomUserDetails(String id, String emailId, String username, String password,
			List<GrantedAuthority> authorities) {
		super();
		this.id = id;
		this.emailId = emailId;
		this.username = username;
		this.password = password;
		this.authorities = authorities;
	}

	public String getId() {
		return id;
	}

	public String getEmailId() {
		return emailId;
	}

	@Override
	public String getUsername() {
		return username;
	}

	@Override
	public String getPassword() {
		return password;
	}

	@Override
	public Collection<? extends GrantedAuthority> getAuthorities() {
		return authorities;
	}

	@Override
	public boolean isAccountNonExpired() {
		return true;
	}

	@Override
	public boolean isAccountNonLocked() {
		return true;
	}

	@Override
	public boolean isCredentialsNonExpired() {
		return true;
	}

	@Override
	public boolean isEnabled() {
		return true;
	}

}
