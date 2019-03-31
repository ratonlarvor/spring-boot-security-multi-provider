package io.opph.example;

import io.opph.example.security.AuthenticationFacade;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequiredArgsConstructor
public class HomeController {
    private final AuthenticationFacade authenticationFacade;

    @GetMapping("/")
    public String hello() {
        Authentication authentication = authenticationFacade.getAuthentication();
        UserDetails userDetails = (UserDetails) authentication.getPrincipal();

        return String.format("hello %s\nyour roles are: %s",
                userDetails.getUsername(), userDetails.getAuthorities());
    }
}
