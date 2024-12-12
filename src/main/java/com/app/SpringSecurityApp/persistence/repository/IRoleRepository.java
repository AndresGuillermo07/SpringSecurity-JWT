package com.app.SpringSecurityApp.persistence.repository;

import com.app.SpringSecurityApp.persistence.entity.RoleEntity;
import org.springframework.data.repository.CrudRepository;

import java.util.List;

public interface IRoleRepository extends CrudRepository<RoleEntity, Long> {

    List<RoleEntity> findRoleEntitiesByRoleEnumIn(List<String> roleNames);

}
