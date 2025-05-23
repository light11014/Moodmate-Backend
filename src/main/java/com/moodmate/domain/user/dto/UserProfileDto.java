package com.moodmate.domain.user.dto;

import com.moodmate.domain.user.entity.User;
import lombok.AllArgsConstructor;
import lombok.Getter;

@Getter
@AllArgsConstructor
public class UserProfileDto {
    private String email;
    private String username;
    private String pictureUrl;

    public UserProfileDto(User user) {
        this.email = user.getEmail();
        this.username = user.getUsername();
        this.pictureUrl = user.getPictureUrl();
    }
}
