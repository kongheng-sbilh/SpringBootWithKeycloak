package kh.com.sbilhbank.oauth2.controller;

import kh.com.sbilhbank.oauth2.model.User;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.core.oidc.OidcIdToken;
import org.springframework.security.oauth2.core.oidc.user.DefaultOidcUser;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/")
public class IndexController {

    @GetMapping
    public ResponseEntity<User> index() {
        OAuth2User user = ((OAuth2User) SecurityContextHolder.getContext().getAuthentication().getPrincipal());
        OidcIdToken idToken = ((DefaultOidcUser) user).getIdToken();
        return new ResponseEntity<>(User.builder()
            .name(user.getAttribute("name"))
            .email(user.getAttribute("email"))
            .token(idToken.getTokenValue())
            .build(), HttpStatus.OK);
    }

    @GetMapping("/unauthenticated")
    public ResponseEntity<String> unauthenticatedRequests() {
        return new ResponseEntity<>("This is unauthenticated endpoint", HttpStatus.OK);
    }

    @GetMapping("/products")
    public ResponseEntity<String> products() {
        return new ResponseEntity<>("Products", HttpStatus.OK);
    }

    @GetMapping("/customers")
    public ResponseEntity<String> customers() {
        return new ResponseEntity<>("Customers", HttpStatus.OK);
    }
}