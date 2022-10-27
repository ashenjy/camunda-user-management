package com.cn.camunda.usermanagement.repository;


import com.cn.camunda.usermanagement.models.ERole;
import com.cn.camunda.usermanagement.models.Role;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface RoleRepository extends JpaRepository<Role, Long> {
  Optional<Role> findByName(ERole name);
}
