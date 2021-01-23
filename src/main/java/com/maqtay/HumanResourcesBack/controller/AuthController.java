package com.maqtay.HumanResourcesBack.controller;

import javax.servlet.http.HttpServletRequest;
import javax.validation.*;

import com.maqtay.HumanResourcesBack.models.ConfigurationToken;
import com.maqtay.HumanResourcesBack.models.ERole;
import com.maqtay.HumanResourcesBack.models.Role;
import com.maqtay.HumanResourcesBack.models.User;
import com.maqtay.HumanResourcesBack.repository.ConfirmationTokenRepository;
import com.maqtay.HumanResourcesBack.security.services.EmailSenderService;
import org.apache.logging.log4j.message.SimpleMessage;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.http.ResponseEntity;
import org.springframework.mail.SimpleMailMessage;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.validation.Errors;
import org.springframework.web.bind.annotation.*;

import com.maqtay.HumanResourcesBack.payload.request.LoginRequest;
import com.maqtay.HumanResourcesBack.payload.request.SignupRequest;
import com.maqtay.HumanResourcesBack.payload.response.JwtResponse;
import com.maqtay.HumanResourcesBack.payload.response.MessageResponse;
import com.maqtay.HumanResourcesBack.repository.RoleRepository;
import com.maqtay.HumanResourcesBack.repository.UserRepository;
import com.maqtay.HumanResourcesBack.security.jwt.JwtUtils;
import com.maqtay.HumanResourcesBack.security.services.UserDetailsImpl;
import org.springframework.web.servlet.ModelAndView;

import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

@CrossOrigin(origins = "*", maxAge = 3600)
@RestController
@RequestMapping("/api/auth")
public class AuthController {
    @Autowired
    AuthenticationManager authenticationManager;

    @Autowired
    UserRepository userRepository;

    @Autowired
    RoleRepository roleRepository;

    @Autowired
    PasswordEncoder passwordEncoder;

    @Autowired
    JwtUtils jwtUtils;

    @Autowired
    ConfirmationTokenRepository confirmationTokenRepository;

    @Autowired
    EmailSenderService emailSenderService;

    @PostMapping("/signin")
    public ResponseEntity<?> authenticateUser(@Valid @RequestBody LoginRequest loginRequest) {

        User user = new User(loginRequest.getUsername(), loginRequest.getUsername(), loginRequest.getPassword());
        if (user.isEnabled()) {
            Authentication authentication = authenticationManager.authenticate(
                    new UsernamePasswordAuthenticationToken(loginRequest.getUsername(), loginRequest.getPassword())
            );

            SecurityContextHolder.getContext().setAuthentication(authentication);
            String jwt = jwtUtils.generateJwtToken(authentication);

            UserDetailsImpl userDetails = (UserDetailsImpl) authentication.getPrincipal();
            List<String> roles = userDetails.getAuthorities().stream()
                    .map(item -> item.getAuthority())
                    .collect(Collectors.toList());

            return ResponseEntity.ok(new JwtResponse(jwt,
                    userDetails.getId(),
                    userDetails.getUsername(),
                    userDetails.getEmail(),
                    roles
            ));
        } else {
            return ResponseEntity.status(401).body("Email not verified!");
        }

    }

    @PostMapping("/signup")
    public ResponseEntity<?> registerUser(@Valid @RequestBody SignupRequest signupRequest) {
        if (userRepository.existsByUsername(signupRequest.getUsername())) {
            return ResponseEntity
                    .badRequest()
                    .body(new MessageResponse("Error: Username is already exists!"));
        }
        if (userRepository.existsByEmail(signupRequest.getEmail())) {
            return ResponseEntity
                    .badRequest()
                    .body(new MessageResponse("Error: Email is already exists!"));
        }

        User user = new User(signupRequest.getUsername(),
                    signupRequest.getEmail(),
                    passwordEncoder.encode(signupRequest.getPassword()));
        
        Set<String> strRoles = signupRequest.getRole();
        Set<Role> roles = new HashSet<>();

        if(strRoles == null) {
            Role userRole = roleRepository.findByName(ERole.ROLE_USER)
                    .orElseThrow(() -> new RuntimeException("Error: Role is not found!"));
            roles.add(userRole);
        } else {
            strRoles.forEach(role -> {
                switch (role) {
                    case "admin":
                        Role adminRole = roleRepository.findByName(ERole.ROLE_ADMIN)
                                .orElseThrow(() -> new RuntimeException("Error: Role is not found!"));
                        roles.add(adminRole);
                        break;
                    case "mod":
                        Role modeRole = roleRepository.findByName(ERole.ROLE_MODERATOR)
                                .orElseThrow(() -> new RuntimeException("Error: Role is not found!"));
                        roles.add(modeRole);
                        break;
                    default:
                        Role userRole = roleRepository.findByName(ERole.ROLE_USER)
                                .orElseThrow(() -> new RuntimeException("Error: Role is not found!"));
                        roles.add(userRole);
                }
            });
        }

        user.setRoles(roles);
        userRepository.save(user);

        ConfigurationToken configurationToken = new ConfigurationToken(user);
        confirmationTokenRepository.save(configurationToken);
        SimpleMailMessage mailMessage = new SimpleMailMessage();
        mailMessage.setTo(user.getEmail());
        mailMessage.setSubject("Kayıt işlemini tamamla!");
        mailMessage.setFrom("maktay3@gmail.com");
        mailMessage.setText("Kayıt işlemini tamamlamak için lütfen aşağıdaki linke tıklayın. 24 saat sonra geçerliliği bitecektir. " +
                "http://localhost:3306/confirm-account?token"+configurationToken.getConfirmationToken());
        emailSenderService.sendMail(mailMessage);

        return ResponseEntity.ok(new MessageResponse("User registered successfully!"));
    }

    @RequestMapping(value = "confirm-account", method = {RequestMethod.GET, RequestMethod.POST})
    public ResponseEntity<?> confirmUserAccount(@RequestParam("token")String confirmationToken) {
        ConfigurationToken token = confirmationTokenRepository.findByConfirmationToken(confirmationToken);

        if (token != null) {
            User user = userRepository.findByEmail(token.getUser().getEmail());
            user.setEnabled(true);
            userRepository.save(user);
            return ResponseEntity.ok(new MessageResponse("Email verification successfully!"));
        } else {
            return ResponseEntity.status(401).body("Email token verification failed!");
        }
    }
}
