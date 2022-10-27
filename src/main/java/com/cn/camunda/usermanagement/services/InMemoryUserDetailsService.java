//package com.cn.camunda.usermanagement.auth.common;
//
//import org.springframework.context.annotation.Bean;
//import org.springframework.context.annotation.Configuration;
//import org.springframework.security.core.userdetails.User;
//import org.springframework.security.core.userdetails.UserDetailsService;
//import org.springframework.security.provisioning.InMemoryUserDetailsManager;
//
//@Configuration
//public class InMemoryUserDetailsService {
//
//    //    org.springframework.security.core.userdetails.User [Username=demo, Password=[PROTECTED], Enabled=true,
////    AccountNonExpired=true, credentialsNonExpired=true, AccountNonLocked=true, Granted Authorities=[ROLE_ACTUATOR, ROLE_camunda-admin]]
//    // This is just a very simple Identity Management solution for demo purposes.
//    // In real world scenarios, this would be replaced by the actual IAM solution
//    @Bean
//    public UserDetailsService userDetailsService() {
//        InMemoryUserDetailsManager manager = new InMemoryUserDetailsManager();
//        //INFO: https://stackoverflow.com/questions/49654143/spring-security-5-there-is-no-passwordencoder-mapped-for-the-id-null
//        manager.createUser(User.withUsername("demo").password("{noop}demo").roles("ACTUATOR", "camunda-admin").build());
//        manager.createUser(User.withUsername("john").password("{noop}john").roles("camunda-user").build());
//        return manager;
//    }
//
//}