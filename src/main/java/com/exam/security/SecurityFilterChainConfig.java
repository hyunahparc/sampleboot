package com.exam.security;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
public class SecurityFilterChainConfig {

	@Bean
	public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
		
		// 커스터마이징 처리
		
		// 1. 불필요한 인증제거
		http.authorizeHttpRequests()
			.antMatchers("/login","/home","/webjars/**","/signup","/images/**").permitAll()
			.anyRequest()
			.authenticated();
		
		// 2. 로그인 관련 작업
		http.formLogin() // 사용자가 만든 로그인 화면으로 쓰겠음
			.loginPage("/login") // 로그인 페이지로 가는 요청맵핑값
			.loginProcessingUrl("/auth") // <form action="auth" method="post"
			.usernameParameter("userid")
			.passwordParameter("passwd")
			.failureForwardUrl("/login_fail") // 로그인 실패시 리다이렉트되는 요청맵핑값
			//.successForwardUrl("/login_success"); // 로그인 성공시 리다이렉트되는 요청맵핑값
			.defaultSuccessUrl("/login_success", true); // 로그인 성공시 리다이렉트되는 요청맵핑값
		
		// 3. csrf 비활성화
		http.csrf().disable();
		
		
		// 4. 로그아웃 관련 작업
		http.logout()
			.logoutUrl("/logout") // 시큐리티가 자동으로 로그아웃 처리해주는 맵핑값
			.logoutSuccessUrl("/home");
		
		return http.build();
	}
}
