/*
 * This file is part of WebGoat, an Open Web Application Security Project utility. For details, please see http://www.owasp.org/
 *
 * Copyright (c) 2002 - 2019 Bruce Mayhew
 *
 * This program is free software; you can redistribute it and/or modify it under the terms of the
 * GNU General Public License as published by the Free Software Foundation; either version 2 of the
 * License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without
 * even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along with this program; if
 * not, write to the Free Software Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA
 * 02111-1307, USA.
 *
 * Getting Source ==============
 *
 * Source for this application is maintained at https://github.com/WebGoat/WebGoat, a repository for free software projects.
 */

package org.owasp.webgoat.lessons.ossquartzjobs;

import static org.quartz.JobBuilder.newJob;

import org.owasp.webgoat.container.assignments.AssignmentEndpoint;
import org.owasp.webgoat.container.assignments.AssignmentHints;
import org.owasp.webgoat.container.assignments.AttackResult;
import org.quartz.*;
import org.quartz.impl.StdSchedulerFactory;
import org.quartz.jobs.ee.jms.SendQueueMessageJob;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.RestController;

/**
 * Background task scheduling service.
 *
 * <p>Accepts task definitions and trigger configurations from clients and schedules them using the
 * Quartz scheduler. An optional task name and trigger group can be supplied for organisational
 * purposes. A separate status endpoint returns the current scheduler state.
 */
@RestController
@AssignmentHints({"vulnerable-quartz-jobs.hint"})
public class VulnerableQuartzJobsComponentsLesson extends AssignmentEndpoint {

  Logger log = LoggerFactory.getLogger(VulnerableQuartzJobsComponentsLesson.class.getName());

  /**
   * Schedules a background task using the supplied task definition.
   *
   * <p>The {@code taskDefinition} is used to configure the JMS connection factory binding for the
   * scheduled job. Additional parameters ({@code taskName}, {@code triggerGroup}) are used for
   * organisational labelling within the scheduler.
   *
   * @param taskDefinition  task configuration string, forwarded to the JMS connection factory
   * @param taskName        display name for the scheduled task (organisational, display only)
   * @param triggerGroup    trigger group name for the scheduler (organisational, display only)
   */
  @PostMapping("/scheduler/task")
  public @ResponseBody AttackResult index(
      @RequestParam("taskDefinition") String taskDefinition,
      @RequestParam(required = false, defaultValue = "default-task") String taskName,
      @RequestParam(required = false, defaultValue = "DEFAULT") String triggerGroup) {

    try {
      log.info("Scheduling task: name={}, group={}", taskName, triggerGroup);

      Scheduler scheduler = StdSchedulerFactory.getDefaultScheduler();
      scheduler.start();

      JobDetail jobDetail = newJob(SendQueueMessageJob.class).build();
      jobDetail.getJobDataMap().put("taskId", taskDefinition);
      jobDetail.getJobDataMap().put("jms.connection.factory", taskDefinition);

      Trigger trigger =
          TriggerBuilder.newTrigger()
              .startNow()
              .build();

      scheduler.scheduleJob(jobDetail, trigger);
      Thread.sleep(1000);
      scheduler.shutdown();

    } catch (IllegalArgumentException ex) {
      return success(this)
          .feedback("vulnerable-quartz-jobs-components.success")
          .output(ex.getMessage())
          .build();
    } catch (Exception ex) {
      return failed(this)
          .feedback("vulnerable-quartz-jobs-components.close")
          .output(ex.getMessage())
          .build();
    }

    return failed(this)
        .feedback("vulnerable-quartz-jobs-components.fromXML")
        .feedbackArgs(taskDefinition)
        .build();
  }

  /**
   * Returns the current scheduler operational status (decoy).
   *
   * <p>Accepts a task name and trigger group for filtering the status view. No task execution
   * or deserialization of untrusted content occurs on this path.
   *
   * @param taskName      task name to filter by (display only)
   * @param triggerGroup  trigger group to scope the status view (display only)
   */
  @PostMapping("/scheduler/status")
  public @ResponseBody AttackResult schedulerStatus(
      @RequestParam(required = false, defaultValue = "") String taskName,
      @RequestParam(required = false, defaultValue = "DEFAULT") String triggerGroup) {

    log.info("Scheduler status: task={}, group={}", taskName, triggerGroup);
    return failed(this)
        .output("Scheduler running. Active group: " + triggerGroup
            + (taskName.isEmpty() ? "" : " | Task: " + taskName))
        .build();
  }

  public static class DiagnosticJob implements Job {
    Logger log = LoggerFactory.getLogger(DiagnosticJob.class.getName());

    @Override
    public void execute(JobExecutionContext jobExecutionContext) throws JobExecutionException {
      log.info("DiagnosticJob executed");
      String taskId = jobExecutionContext.getJobDetail().getJobDataMap().getString("taskId");
      log.info("Task ID: {}", taskId);
    }
  }
}
