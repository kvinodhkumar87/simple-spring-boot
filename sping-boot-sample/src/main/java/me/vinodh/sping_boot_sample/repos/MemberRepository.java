package me.vinodh.sping_boot_sample.repos;

import org.springframework.data.repository.PagingAndSortingRepository;

import me.vinodh.sping_boot_sample.domain.User;

public interface MemberRepository extends PagingAndSortingRepository<User, String> {

	public User findByEmail(String email);

}
