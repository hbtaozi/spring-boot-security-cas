package com.example.config;

import java.util.ArrayList;
import java.util.List;

import org.springframework.security.cas.authentication.CasAssertionAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.AuthenticationUserDetailsService;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UsernameNotFoundException;

public class UserDetailsServiceImpl implements AuthenticationUserDetailsService<CasAssertionAuthenticationToken> {

	@Override
	public UserDetails loadUserDetails(CasAssertionAuthenticationToken token) throws UsernameNotFoundException {
		
		System.out.println("token.getName()="+token.getName());
		
		if (token.getName().equalsIgnoreCase("xiangtao")) {
			List<GrantedAuthority> authorities = new ArrayList<>();
			authorities.add(new SimpleGrantedAuthority(AuthoritiesConstants.USER));
			return new User(token.getName(), token.getCredentials().toString(), authorities);
		} else if (token.getName().equalsIgnoreCase("xiangtao1")) {
			List<GrantedAuthority> authorities = new ArrayList<>();
			authorities.add(new SimpleGrantedAuthority(AuthoritiesConstants.ADMIN));
			return new User(token.getName(), token.getCredentials().toString(), authorities);
		} else {
			List<GrantedAuthority> authorities = new ArrayList<>();
			authorities.add(new SimpleGrantedAuthority(AuthoritiesConstants.ANONYMOUS));
			return new User(token.getName(), token.getCredentials().toString(), authorities);
		}

	}
}
