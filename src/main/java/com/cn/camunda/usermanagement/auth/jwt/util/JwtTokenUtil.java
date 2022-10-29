package com.cn.camunda.usermanagement.auth.jwt.util;

import com.cn.camunda.usermanagement.services.UserDetailsImpl;
import io.jsonwebtoken.*;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.io.IOUtils;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.ResponseCookie;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;
import org.springframework.web.util.WebUtils;

import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import java.io.InputStream;
import java.io.Serializable;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.function.Function;
import java.util.stream.Collectors;

@Component
@Slf4j
public class JwtTokenUtil implements Serializable {

    private static final long serialVersionUID = -2550185165626007488L;

//    public static final long JWT_TOKEN_VALIDITY = 60; //1 minute
    //5 * 60 * 60 -> 5 minutes

    @Value("${application.jwt.secret-path}")
    private String jwtSecretPath;

    @Value("${application.jwt.expiration-ms}")
    private int jwtExpirationMs;

    @Value("${application.jwt.cookie-name}")
    private String jwtCookie;

    public String getJwtFromCookies(HttpServletRequest request) {
        Cookie cookie = WebUtils.getCookie(request, jwtCookie);
        if (cookie != null) {
            return cookie.getValue();
        } else {
            return null;
        }
    }

    public ResponseCookie generateJwtCookie(UserDetailsImpl userPrincipal) {
        String jwt = generateTokenFromUsername(userPrincipal.getUsername());
        ResponseCookie cookie = ResponseCookie.from(jwtCookie, jwt).path("/api").maxAge(24 * 60 * 60).httpOnly(true).build();
        return cookie;
    }

    public ResponseCookie getCleanJwtCookie() {
        ResponseCookie cookie = ResponseCookie.from(jwtCookie, null).path("/api").build();
        return cookie;
    }

    public String getUsernameFromToken(String token) {
        return getClaimFromToken(token, Claims::getSubject);
    }

    public String getPasswordFromToken(String token) {
        Claims body = getAllClaimsFromToken(token);
        if(body.get("password") instanceof String) {
            return (String) body.get("password");
        }
        log.error("ERROR: Unable to load 'password' from JWT Token");
        return null;
    }

    public List<String> getAuthoritiesFromToken(String token) {
        Claims body = getAllClaimsFromToken(token);
        if(body.get("authorities") instanceof List) {
            return (List<String>) body.get("authorities");
        }
        log.error("ERROR: Unable to load granted 'authorities' from JWT Token");
        return null;
    }

    public Date getIssuedAtDateFromToken(String token) {
        return getClaimFromToken(token, Claims::getIssuedAt);
    }

    public Date getExpirationDateFromToken(String token) {
        return getClaimFromToken(token, Claims::getExpiration);
    }

    public <T> T getClaimFromToken(String token, Function<Claims, T> claimsResolver) {
        final Claims claims = getAllClaimsFromToken(token);
        return claimsResolver.apply(claims);
    }

    private Claims getAllClaimsFromToken(String token) {

        return Jwts.parser().setSigningKey(extractJwtSecret(jwtSecretPath)).parseClaimsJws(token).getBody();
    }

//    private Boolean isTokenExpired(String token) {
//        final Date expiration = getExpirationDateFromToken(token);
//        return expiration.before(new Date());
//    }

    private Boolean ignoreTokenExpiration(String token) {
        // here you specify tokens, for that the expiration is ignored
        return false;
    }

    public String generateToken(UserDetails ud) {
        Map<String, Object> claims = Jwts.claims().setSubject(ud.getUsername());
        //TODO: remove adding sensitive info to jwt token
        claims.put("password", ud.getPassword());
        claims.put("authorities", ud.getAuthorities().stream().map(GrantedAuthority::getAuthority).collect(Collectors.toList()));
//        claims.put("authorities", ud.getAuthorities());

        return doGenerateToken(claims, ud.getUsername());
    }

    private String doGenerateToken(Map<String, Object> claims, String subject) {

        return Jwts.builder().setClaims(claims).setSubject(subject).setIssuedAt(new Date(System.currentTimeMillis()))
                .setExpiration(new Date(System.currentTimeMillis() + jwtExpirationMs)).signWith(SignatureAlgorithm.HS512, extractJwtSecret(jwtSecretPath)).compact();
    }

    public Boolean canTokenBeRefreshed(String token) {
        return (!isTokenExpired(token) || ignoreTokenExpiration(token));
    }

    public Boolean validateToken(String token, UserDetails userDetails) {
        final String username = getUsernameFromToken(token);
        return (username.equals(userDetails.getUsername()) && !isTokenExpired(token));
    }

    private Boolean isTokenExpired(String authToken) {
        try {
            Jwts.parser().setSigningKey(extractJwtSecret(jwtSecretPath)).parseClaimsJws(authToken);
            return false;
        } catch (SignatureException e) {
            log.error("Invalid JWT signature: {}", e.getMessage());
        } catch (MalformedJwtException e) {
            log.error("Invalid JWT token: {}", e.getMessage());
        } catch (ExpiredJwtException e) {
            log.error("JWT token is expired: {}", e.getMessage());
        } catch (UnsupportedJwtException e) {
            log.error("JWT token is unsupported: {}", e.getMessage());
        } catch (IllegalArgumentException e) {
            log.error("JWT claims string is empty: {}", e.getMessage());
        }
        return true;
    }

    //TODO: Auto extract secret at app startup
    private String extractJwtSecret(String jwtSecretPath) {
        String jwtSecret = null;
        if (jwtSecretPath != null) {
            try {
                InputStream inStream = Files.newInputStream(Paths.get(jwtSecretPath));
                jwtSecret = IOUtils.toString(inStream, StandardCharsets.UTF_8);
            } catch (Exception e) {
                log.error("ERROR: Unable to load JWT Secret: " + e.getLocalizedMessage());
            }
        }
        return jwtSecret;
    }

    public UserDetails getUserDetailsFromToken(String username, String jwtToken) {
        List<String> au = getAuthoritiesFromToken(jwtToken);
        for (int i = 0; i < au.size(); i++) {
            String authority = au.get(i);
            if (authority.startsWith("ROLE_")) {
                au.set(i, authority.replaceAll("ROLE_", ""));
            }
        }
        String[] roles = new String[au.size()];

        return User.withUsername(username).password(getPasswordFromToken(jwtToken)).roles(au.toArray(roles)).build();
    }

    public String generateTokenFromUsername(String username) {
        return Jwts.builder()
                .setSubject(username)
                .setIssuedAt(new Date())
                .setExpiration(new Date((new Date()).getTime() + jwtExpirationMs))
                .signWith(SignatureAlgorithm.HS512, extractJwtSecret(jwtSecretPath))
                .compact();
    }
}
