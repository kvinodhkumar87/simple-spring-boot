package me.vinodh.sping_boot_sample.services;

import java.util.ArrayList;
import java.util.List;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import me.vinodh.sping_boot_sample.domain.CustomUserDetails;
import me.vinodh.sping_boot_sample.domain.User;
import me.vinodh.sping_boot_sample.repos.MemberRepository;

@Service
public class CustomUserDetailsService implements UserDetailsService {

	@Autowired
	private MemberRepository memberRepository;

	@Override
	public UserDetails loadUserByUsername(String emailId) throws UsernameNotFoundException {
		User member = memberRepository.findByEmail(emailId);
		if (member != null) {
			String id = member.getId();
			String name = member.getName();
			String username = member.getEmail();
			String password = member.getPassword();
			List<String> roles = new ArrayList<String>();
			List<GrantedAuthority> authority = null;
			if (roles != null) {
				authority = AuthorityUtils.createAuthorityList(roles.toArray(new String[roles.size()]));
			}
			String status = member.getStatus();
			return new CustomUserDetails(id, emailId, username, password, authority);
		} else {
			throw new UsernameNotFoundException("User not exists - Email Id:" + emailId);
		}
	}

}
