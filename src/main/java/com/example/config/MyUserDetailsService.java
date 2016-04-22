package com.example.config;

import java.util.ArrayList;
import java.util.List;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UsernameNotFoundException;

public class MyUserDetailsService  implements org.springframework.security.core.userdetails.UserDetailsService{

	@Override
	public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
		System.out.println("username="+username);
		
		if (username.equalsIgnoreCase("xiangtao")) {
			List<GrantedAuthority> authorities = new ArrayList<>();
			authorities.add(new SimpleGrantedAuthority(AuthoritiesConstants.USER));
			return new User(username, "", authorities);
		} else if (username.equalsIgnoreCase("xiangtao1")) {
			List<GrantedAuthority> authorities = new ArrayList<>();
			authorities.add(new SimpleGrantedAuthority(AuthoritiesConstants.ADMIN));
			return new User(username, "", authorities);
		} else {
			List<GrantedAuthority> authorities = new ArrayList<>();
			authorities.add(new SimpleGrantedAuthority(AuthoritiesConstants.ANONYMOUS));
			return new User(username, "", authorities);
		}
	}

}
