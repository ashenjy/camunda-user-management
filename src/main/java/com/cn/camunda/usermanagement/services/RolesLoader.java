package com.cn.camunda.usermanagement.services;

import com.cn.camunda.usermanagement.models.ERole;
import com.cn.camunda.usermanagement.models.Role;
import com.cn.camunda.usermanagement.repository.RoleRepository;
import com.cn.camunda.usermanagement.repository.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.ApplicationArguments;
import org.springframework.boot.ApplicationRunner;
import org.springframework.boot.CommandLineRunner;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.stereotype.Component;

import javax.annotation.PostConstruct;

@Component
public class RolesLoader implements CommandLineRunner {

    @Autowired
    private RoleRepository roleRepository;

//    @Autowired
//    public DataLoader(UserRepository userRepository) {
//        this.userRepository = userRepository;
//    }

    private void saveRoles() {
        if (!roleRepository.findByName(ERole.ROLE_ADMIN).isPresent()) {
            Role admin = new Role();
//            admin.setId(1);
            admin.setName(ERole.ROLE_ADMIN);
            roleRepository.save(admin);
        }
        if (!roleRepository.findByName(ERole.ROLE_USER).isPresent()) {
            Role user = new Role();
//            user.setId(2);
            user.setName(ERole.ROLE_USER);
            roleRepository.save(user);
        }
        if (!roleRepository.findByName(ERole.ROLE_MODERATOR).isPresent()) {
            Role mod = new Role();
//            mod.setId(3);
            mod.setName(ERole.ROLE_MODERATOR);
            roleRepository.save(mod);
        }
    }

    @Override
    public void run(String... args) throws Exception {
        saveRoles();
    }
}
