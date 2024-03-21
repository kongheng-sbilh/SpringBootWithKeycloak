package kh.com.sbilhbank.oauth2.controller;

import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.core.oidc.OidcIdToken;
import org.springframework.security.oauth2.core.oidc.user.DefaultOidcUser;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.HashMap;

@RestController
@RequestMapping("/")
public class IndexController {

    @GetMapping
    public HashMap index() {
        OAuth2User user = ((OAuth2User) SecurityContextHolder.getContext().getAuthentication().getPrincipal());
        OidcIdToken idToken = ((DefaultOidcUser) user).getIdToken();
        return new HashMap(){{
            put("hello", user.getAttribute("name"));
            put("your email is", user.getAttribute("email"));
            put("your token is", idToken.getTokenValue());
        }};
    }

    @GetMapping("/unauthenticated")
    public HashMap unauthenticatedRequests() {
        return new HashMap(){{
            put("this is ", "unauthenticated endpoint");
        }};
    }

    @GetMapping("/products")
    public String products() {
        return "products";
    }

    @GetMapping("/customers")
    public String customers() {
        return "customers";
    }
}