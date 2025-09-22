package com.klu;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.*;
import org.springframework.transaction.annotation.Transactional;
import java.time.LocalDateTime;
import java.util.Map;
import java.util.Optional;
import java.util.Random;
import java.util.UUID;

@RestController
@RequestMapping("/api/auth")
public class AuthController {

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final OtpRepository otpRepository;  // New repository for OTPs

    @Autowired
    public AuthController(UserRepository userRepository, PasswordEncoder passwordEncoder, OtpRepository otpRepository) {
        this.userRepository = userRepository;
        this.passwordEncoder = passwordEncoder;
        this.otpRepository = otpRepository;
    }

    // ------------------ Existing Signup/Login ------------------

    // Regular User Signup
    @PostMapping("/signup")
    public ResponseEntity<String> signUp(@RequestBody User user) {
        if (userRepository.existsByEmail(user.getEmail())) {
            return ResponseEntity.status(HttpStatus.CONFLICT).body("Email already exists");
        }
        
        user.setPassword(passwordEncoder.encode(user.getPassword()));
        user.setRole("USER");
        userRepository.save(user);
        return ResponseEntity.ok("User registered successfully");
    }

    // Admin Signup
    @PostMapping("/admin/signup")
    public ResponseEntity<String> adminSignUp(@RequestBody User user) {
        if (userRepository.existsByEmail(user.getEmail())) {
            return ResponseEntity.status(HttpStatus.CONFLICT).body("Email already exists");
        }

        user.setPassword(passwordEncoder.encode(user.getPassword()));
        user.setRole("ADMIN");
        userRepository.save(user);
        return ResponseEntity.ok("Admin registered successfully");
    }

    // Normal Login
    @PostMapping("/login")
    public ResponseEntity<String> login(@RequestBody User loginRequest) {
        User user = userRepository.findByEmail(loginRequest.getEmail())
                .orElseThrow(() -> new RuntimeException("User not found"));
        
        if (!passwordEncoder.matches(loginRequest.getPassword(), user.getPassword())) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("Invalid credentials");
        }
        
        return ResponseEntity.ok("Login successful as " + user.getRole());
    }

    // ------------------ OTP Endpoints ------------------

    // Send OTP
    @PostMapping("/send-otp")
    public ResponseEntity<?> sendOtp(@RequestBody Map<String, String> request) {
        String email = request.get("email");
        if(email == null || email.isEmpty()) {
            return ResponseEntity.badRequest().body(Map.of("message", "Email is required"));
        }

        // Check if user exists
        if(!userRepository.existsByEmail(email)) {
            return ResponseEntity.status(HttpStatus.NOT_FOUND)
                    .body(Map.of("message", "User not found"));
        }

        // Generate 6-digit OTP
        String otpCode = String.format("%06d", new Random().nextInt(999999));

        // Save OTP to database
        Otp otp = new Otp();
        otp.setEmail(email);
        otp.setCode(otpCode);
        otp.setExpiryTime(LocalDateTime.now().plusMinutes(5));
        otpRepository.save(otp);

        // TODO: Replace this with actual email sending
        System.out.println("OTP for " + email + ": " + otpCode);

        return ResponseEntity.ok(Map.of("message", "OTP sent successfully"));
    }

    // Verify OTP
    @PostMapping("/verify-otp")
    @Transactional
    public ResponseEntity<?> verifyOtp(@RequestBody Map<String, String> request) {
        String email = request.get("email");
        String code = request.get("otp");

        Optional<Otp> otpOpt = otpRepository.findByEmailAndCode(email, code);
        if(otpOpt.isEmpty()) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                    .body(Map.of("message", "Invalid OTP"));
        }

        Otp otp = otpOpt.get();
        if(otp.getExpiryTime().isBefore(LocalDateTime.now())) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                    .body(Map.of("message", "OTP expired"));
        }

        // Delete OTP after successful verification
        otpRepository.deleteByEmail(email);

        // Generate simple token (for demo purposes)
        String token = UUID.randomUUID().toString();

        return ResponseEntity.ok(Map.of("message", "OTP verified", "token", token));
    }
}
