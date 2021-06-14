package com.micro.service.endpoint.repository;

import com.micro.service.endpoint.model.Course;
import org.springframework.data.repository.PagingAndSortingRepository;

public interface CourseRepository extends PagingAndSortingRepository<Course, Long> {
}
