package com.app.SpringSecurityApp.service;


import com.app.SpringSecurityApp.controller.dto.AuthCreateUserRequest;
import com.app.SpringSecurityApp.controller.dto.AuthResponse;
import com.app.SpringSecurityApp.controller.dto.AuthLoginRequest;
import com.app.SpringSecurityApp.persistence.entity.RoleEntity;
import com.app.SpringSecurityApp.persistence.entity.UserEntity;
import com.app.SpringSecurityApp.persistence.repository.IRoleRepository;
import com.app.SpringSecurityApp.persistence.repository.IUserRepository;
import com.app.SpringSecurityApp.util.JwtUtils;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;


@Service
public class UserDetailServiceImpl implements UserDetailsService {

    private final IRoleRepository roleRepository;
    private final PasswordEncoder passwordEncoder;
    private final IUserRepository userRepository;
    private final JwtUtils jwtUtils;

    public UserDetailServiceImpl(IRoleRepository roleRepository, PasswordEncoder passwordEncoder, IUserRepository userRepository, JwtUtils jwtUtils) {
        this.roleRepository = roleRepository;
        this.passwordEncoder = passwordEncoder;
        this.userRepository = userRepository;
        this.jwtUtils = jwtUtils;
    }


    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {

        UserEntity userEntity = userRepository.findUserEntityByUsername(username).orElseThrow(
                () -> new UsernameNotFoundException("The user: " + username + " was not found")
        );

        List<SimpleGrantedAuthority> authorities = new ArrayList<>();

        userEntity.getRoles().forEach(role -> authorities.add(
                new SimpleGrantedAuthority("ROLE_".concat(
                        role.getRoleEnum().name()
                )
                )));

        userEntity.getRoles().stream()
                .flatMap(role -> role.getPermissionList().stream())
                .forEach(permission -> authorities.add(new SimpleGrantedAuthority(permission.getName())));

        return new User(userEntity.getUsername(),
                userEntity.getPassword(),
                userEntity.getIsEnable(),
                userEntity.getAccountNonExpired(),
                userEntity.getCredentialsNonExpired(),
                userEntity.getAccountNonLocked(),
                authorities
        );
    }

    private Authentication authenticate(String username, String password) {
        UserDetails userDetails = loadUserByUsername(username);

        if (userDetails == null) {
            throw new UsernameNotFoundException("The user: " + username + " was not found");
        }

        if(!passwordEncoder.matches(password, userDetails.getPassword())) {
            throw new BadCredentialsException("Invalid password.");
        }

        return new UsernamePasswordAuthenticationToken(username,userDetails.getPassword(),userDetails.getAuthorities());

    }

    public AuthResponse loginUser(AuthLoginRequest loginRequest) {
        String username = loginRequest.username();
        String password = loginRequest.password();

        Authentication authentication = this.authenticate(username,password);
        SecurityContextHolder.getContext().setAuthentication(authentication);

        String accessToken = jwtUtils.createToken(authentication);

        return new AuthResponse(username,"User logged successfully",accessToken,true);
    }

    public AuthResponse createUser(AuthCreateUserRequest authCreateUser) {

        String username = authCreateUser.username();
        String password = authCreateUser.password();
        List<String> roleRequest = authCreateUser.roleRequest().roleListName();


        Set<RoleEntity> roleEntitySet = new HashSet<>(roleRepository.findRoleEntitiesByRoleEnumIn(roleRequest));

        if(roleEntitySet.isEmpty()) {
            throw new IllegalArgumentException("The roles specified do not exist");
        }

        UserEntity userEntity = UserEntity.builder()
                .username(username)
                .password(passwordEncoder.encode(password))
                .isEnable(true)
                .accountNonExpired(true)
                .accountNonLocked(true)
                .credentialsNonExpired(true)
                .roles(roleEntitySet)
                .build();

        UserEntity userCreated = userRepository.save(userEntity);

        ArrayList<SimpleGrantedAuthority> authorityList = new ArrayList<>();

        userCreated.getRoles().forEach(role -> {
            authorityList.add(new SimpleGrantedAuthority("ROLE_".concat(role.getRoleEnum().name())));
        });

        userCreated.getRoles()
                .stream()
                .flatMap(role -> role.getPermissionList().stream())
                .forEach(permission -> authorityList.add(new SimpleGrantedAuthority(permission.getName())));

        Authentication authentication = new UsernamePasswordAuthenticationToken(userCreated.getUsername(),userCreated.getPassword(),authorityList);

        String accessToken = jwtUtils.createToken(authentication);

          return new AuthResponse(userCreated.getUsername(),"User created successfully",accessToken,true);
    }
}
