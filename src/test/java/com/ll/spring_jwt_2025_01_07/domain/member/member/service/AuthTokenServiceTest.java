package com.ll.spring_jwt_2025_01_07.domain.member.member.service;

import com.ll.spring_jwt_2025_01_07.domain.member.member.entity.Member;
import com.ll.spring_jwt_2025_01_07.domain.member.member.repository.MemberRepository;
import com.ll.spring_jwt_2025_01_07.standard.util.Ut;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.security.Keys;
import jakarta.transaction.Transactional;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.ActiveProfiles;

import java.security.Key;
import java.util.Date;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

@SpringBootTest
@ActiveProfiles("test")
@Transactional
public class AuthTokenServiceTest {
    @Autowired
    private AuthTokenService authTokenService;

    @Autowired
    private MemberRepository memberRepository;

    // 테스트용 토큰 만료기간 : 1년
    private int expireSeconds = 60 * 60 * 24 * 365;
    // 테스트용 토큰 시크릿 키
    private String secret = "abcdefghijklmnopqrstuvwxyz1234567890abcdefghijklmnopqrstuvwxyz1234567890";


    @Test
    @DisplayName("authTokenService 서비스가 존재한다.")
    void t1() {
        assertThat(authTokenService).isNotNull();
    }

    @Test
    @DisplayName("jjwt 로 JWT 생성")
    void t2() {
        Key secretKey = Keys.hmacShaKeyFor(secret.getBytes());

        Claims claims = Jwts.claims()
                .add("name", "Paul")
                .add("age", 23)
                .build();

        Date issuedAt = new Date();
        Date expiration = new Date(issuedAt.getTime() + 1000L * expireSeconds);

        String jwt = Jwts.builder()
                .setClaims(claims)
                .setIssuedAt(issuedAt)
                .setExpiration(expiration)
                .signWith(secretKey, SignatureAlgorithm.HS256)
                .compact();

        assertThat(jwt).isNotBlank();
        System.out.println("jwt = " + jwt);
    }

    @Test
    @DisplayName("")
    void t3() {
        String jwt = Ut.jwt.toString(secret, expireSeconds, Map.of("name", "Paul", "age", 23));
        assertThat(jwt).isNotBlank();
        System.out.println("jwt = " + jwt);
    }

    @Test
    @DisplayName("")
    void t4() {
        Member member = memberRepository.findByUsername("user1").get();

        String accessToken = authTokenService.genAccessToken(member);

        assertThat(accessToken).isNotBlank();
        System.out.println("accessToken = " + accessToken);
    }
}