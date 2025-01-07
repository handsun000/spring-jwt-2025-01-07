package com.ll.spring_jwt_2025_01_07.domain.member.member.service;

import com.ll.spring_jwt_2025_01_07.domain.member.member.entity.Member;
import com.ll.spring_jwt_2025_01_07.domain.member.member.repository.MemberRepository;
import com.ll.spring_jwt_2025_01_07.standard.util.Ut;
import io.jsonwebtoken.*;
import io.jsonwebtoken.security.Keys;
import jakarta.transaction.Transactional;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.ActiveProfiles;

import javax.crypto.SecretKey;
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
        SecretKey secretKey = Keys.hmacShaKeyFor(secret.getBytes());

        Date issuedAt = new Date();
        Date expiration = new Date(issuedAt.getTime() + 1000L * expireSeconds);

        Map<String, Object> payload = Map.of(
                "name", "paul",
                "age",23
        );

        String jwtStr = Jwts.builder()
                .claims(payload)
                .issuedAt(issuedAt)
                .expiration(expiration)
                .signWith(secretKey)
                .compact();

        assertThat(jwtStr).isNotBlank();

        //키가 유효한지 테스트
        Map<String, Object> parsedPayload = (Map<String, Object>) Jwts
                .parser()
                .verifyWith(secretKey)
                .build()
                .parse(jwtStr)
                .getPayload();

        // 키로 부터 payload 를 파싱한 결과가 원래 payload 와 같은지 테스트
        assertThat(parsedPayload).containsAllEntriesOf(payload);
    }

    @Test
    @DisplayName("")
    void t3() {
        Map<String, Object> payload = Map.of("name", "Paul", "age", 23);

        String jwtStr = Ut.jwt.toString(secret, expireSeconds, payload);

        assertThat(jwtStr).isNotBlank();
        assertThat(Ut.jwt.isValid(secret, jwtStr)).isTrue();
        Map<String, Object> parsedPayload = Ut.jwt.payload(secret, jwtStr);
        assertThat(parsedPayload).containsAllEntriesOf(payload);
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