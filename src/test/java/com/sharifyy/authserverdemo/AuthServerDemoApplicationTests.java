package com.sharifyy.authserverdemo;

import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

class AuthServerDemoApplicationTests {

	@Test
	void contextLoads() {
		System.out.println("{bcrypt}"+new BCryptPasswordEncoder().encode("password"));
		System.out.println("{bcrypt}"+new BCryptPasswordEncoder().encode("secret"));
	}

}
