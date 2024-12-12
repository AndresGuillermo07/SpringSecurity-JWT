package com.app.SpringSecurityApp;

import com.app.SpringSecurityApp.persistence.entity.PermissionEntity;
import com.app.SpringSecurityApp.persistence.entity.RoleEntity;
import com.app.SpringSecurityApp.persistence.entity.RoleEnum;
import com.app.SpringSecurityApp.persistence.entity.UserEntity;
import com.app.SpringSecurityApp.persistence.repository.IUserRepository;
import org.springframework.boot.CommandLineRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;

import java.util.Set;

@SpringBootApplication
public class SpringSecurityAppApplication {

	public static void main(String[] args) {
		SpringApplication.run(SpringSecurityAppApplication.class, args);


	}
	@Bean
	CommandLineRunner init(IUserRepository iUserRepository){
		return args ->{

			/* CREATE PERMISSIONS */

			PermissionEntity createPermission = new PermissionEntity().builder()
					.name("CREATE")
					.build();

			PermissionEntity readPermission = new PermissionEntity().builder()
					.name("READ")
					.build();

			PermissionEntity updatePermission = new PermissionEntity().builder()
					.name("UPDATE")
					.build();

			PermissionEntity deletePermission = new PermissionEntity().builder()
					.name("DELETE")
					.build();

			PermissionEntity refactorPermission = new PermissionEntity().builder()
					.name("REFACTOR")
					.build();

			/* CREATE ROLES */

			RoleEntity roleAdmin = new RoleEntity().builder()
					.roleEnum(RoleEnum.ADMIN)
					.permissionList(Set.of(createPermission, readPermission, updatePermission, deletePermission))
					.build();

			RoleEntity roleUser = new RoleEntity().builder()
					.roleEnum(RoleEnum.USER)
					.permissionList(Set.of(createPermission, readPermission))
					.build();

			RoleEntity roleInvited = new RoleEntity().builder()
					.roleEnum(RoleEnum.INVITED)
					.permissionList(Set.of(readPermission))
					.build();

			RoleEntity roleDeveloper = new RoleEntity().builder()
					.roleEnum(RoleEnum.DEVELOPER)
					.permissionList(Set.of(createPermission, readPermission, updatePermission, deletePermission,refactorPermission))
					.build();

			/* CREATE USERS */

			UserEntity userSantiago = new UserEntity().builder()
					.username("santiago")
					.password("$2a$10$h4Dfttk7TLVaXywVjP9cOOPGfWRjB2/CC64ydiaMW13EkoUVc4FhO")
					.isEnable(true)
					.accountNonExpired(true)
					.accountNonLocked(true)
					.credentialsNonExpired(true)
					.roles(Set.of(roleAdmin))
					.build();

			UserEntity userDaniel = new UserEntity().builder()
					.username("daniel")
					.password("$2a$10$h4Dfttk7TLVaXywVjP9cOOPGfWRjB2/CC64ydiaMW13EkoUVc4FhO")
					.isEnable(true)
					.accountNonExpired(true)
					.accountNonLocked(true)
					.credentialsNonExpired(true)
					.roles(Set.of(roleUser))
					.build();

			UserEntity userAndrea = new UserEntity().builder()
					.username("andrea")
					.password("$2a$10$h4Dfttk7TLVaXywVjP9cOOPGfWRjB2/CC64ydiaMW13EkoUVc4FhO")
					.isEnable(true)
					.accountNonExpired(true)
					.accountNonLocked(true)
					.credentialsNonExpired(true)
					.roles(Set.of(roleInvited))
					.build();

			UserEntity userAnyi = new UserEntity().builder()
					.username("anyi")
					.password("$2a$10$h4Dfttk7TLVaXywVjP9cOOPGfWRjB2/CC64ydiaMW13EkoUVc4FhO")
					.isEnable(true)
					.accountNonExpired(true)
					.accountNonLocked(true)
					.credentialsNonExpired(true)
					.roles(Set.of(roleDeveloper))
					.build();

			iUserRepository.saveAll(Set.of(userSantiago,userDaniel,userAndrea,userAnyi));

		};

	}

}
