package com.ppwa.security.clients;

import org.springframework.cloud.openfeign.FeignClient;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;

@FeignClient(name = "user-service", url = "https://ppwa-users.herokuapp.com")
public interface UserFeignClient {

    @GetMapping("/api/users/{username}")
    CustomUser findByUsername(@PathVariable String username);
}
