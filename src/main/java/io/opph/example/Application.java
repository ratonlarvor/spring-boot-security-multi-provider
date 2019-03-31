package io.opph.example;

import io.opph.example.db.User;
import io.opph.example.db.UserRepository;
import lombok.AllArgsConstructor;
import org.springframework.boot.ApplicationArguments;
import org.springframework.boot.ApplicationRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;

@SpringBootApplication
public class Application {

    public static void main(String[] args) {
        SpringApplication.run(Application.class, args);
    }

    @Component
    @AllArgsConstructor
    public class UserLoader implements ApplicationRunner {
        private PasswordEncoder passwordEncoder;
        private final UserRepository userRepository;

        public void run(ApplicationArguments args) {
            userRepository.save(User.builder().login("ykl").password(passwordEncoder.encode("ykl")).withAuthority("ROLE_USER").build());
        }
    }
}
