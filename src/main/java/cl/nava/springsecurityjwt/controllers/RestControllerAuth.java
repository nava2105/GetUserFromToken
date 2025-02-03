package cl.nava.springsecurityjwt.controllers;

import cl.nava.springsecurityjwt.dtos.*;
import cl.nava.springsecurityjwt.factories.IUserFactory;
import cl.nava.springsecurityjwt.models.UsersModel;
import cl.nava.springsecurityjwt.security.JwtGenerador;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;


@RestController
@RequestMapping("/api/auth/")
public class RestControllerAuth {
    private final IUserFactory userFactory;
    private final JwtGenerador jwtGenerador;

    @Autowired
    public RestControllerAuth(IUserFactory userFactory, JwtGenerador jwtGenerador) {
        this.userFactory = userFactory;
        this.jwtGenerador = jwtGenerador;
    }
    // Method to extract user ID from token
    @GetMapping("user_id/token")
    public ResponseEntity<DtoUserIdFromToken> userIdFromToken(HttpServletRequest request) {
        String authHeader = request.getHeader("Authorization");
        if (authHeader == null || !authHeader.startsWith("Bearer ")) {
            return new ResponseEntity<>(HttpStatus.BAD_REQUEST);
        }
        String token = authHeader.substring(7); // Remove "Bearer " prefix
        try {
            if (jwtGenerador.validateToken(token)) {
                String username = jwtGenerador.getUserNameFromJwt(token);
                Long userId = userFactory.findByUserName(username)
                        .map(UsersModel::getUserId)
                        .orElseThrow(() -> new IllegalArgumentException("User not found"));
                DtoUserIdFromToken dtoUserIdFromToken = new DtoUserIdFromToken(userId);
                return new ResponseEntity<>(dtoUserIdFromToken, HttpStatus.OK);
            }
            return new ResponseEntity<>(HttpStatus.UNAUTHORIZED);
        } catch (Exception ex) {
            return new ResponseEntity<>(HttpStatus.UNAUTHORIZED);
        }
    }
}