package cl.nava.springsecurityjwt.dtos;

import lombok.Data;

@Data
public class DtoUserIdFromToken {
    private Long userId;

    public DtoUserIdFromToken(Long userId) { this.userId = userId; }
}
