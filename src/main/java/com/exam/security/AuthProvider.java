package com.exam.security;

import java.util.ArrayList;
import java.util.List;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Component;

import com.exam.dto.Member;
import com.exam.service.MemberService;

@Component
public class AuthProvider implements AuthenticationProvider {

	// 주입
	@Autowired
	MemberService memberService;

	@Override
	public Authentication authenticate(Authentication authentication) throws AuthenticationException {

		String userid = (String) authentication.getPrincipal(); // name="userid" 값
		String passwd = (String) authentication.getCredentials(); // name="passwd" 값

		Member mem = memberService.findById(userid);
		//String encrptPw = mem.getPasswd();

		// Authentication 하위 클래스
		// 로그인 서옥ㅇ시
		UsernamePasswordAuthenticationToken token = null;

		if (mem != null && new BCryptPasswordEncoder().matches(passwd, mem.getPasswd())) {

			List<GrantedAuthority> list = new ArrayList<>();
			list.add(new SimpleGrantedAuthority("USER")); // admin
			
			// 암호화된 비번 대신 raw 비번으로 설정
			mem.setPasswd(passwd);
			token = new UsernamePasswordAuthenticationToken(mem, null, list);
			return token;
		}
		// 로그인 실패시
		throw new BadCredentialsException("비밀번호 불일치");
	}

	@Override
	public boolean supports(Class<?> authentication) {
		return true;
	}

}
