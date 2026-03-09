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
 * <p>Accepts task definitions and scheduling parameters from clients and
 * registers them with the task execution engine. Organisational metadata
 * such as task name, trigger group, priority, and execution window can
 * be supplied to categorise and manage scheduled tasks. A separate status
 * endpoint and history endpoint are available for monitoring without
 * submitting new tasks.
 */
@RestController
@AssignmentHints({"vulnerable-quartz-jobs.hint"})
public class VulnerableQuartzJobsComponentsLesson extends AssignmentEndpoint {

  Logger log = LoggerFactory.getLogger(VulnerableQuartzJobsComponentsLesson.class.getName());

  /**
   * Registers and immediately fires a background task.
   *
   * <p>Accepts a task definition string along with optional organisational
   * metadata. The definition is forwarded to the task execution engine for
   * configuration. Supplementary fields are used for display and routing only.
   *
   * @param taskDefinition   task configuration string
   * @param taskName         display name for the task (organisational only)
   * @param triggerGroup     trigger group identifier (organisational only)
   * @param priority         scheduling priority label (display only)
   * @param executionWindow  preferred execution window label (display only)
   */
  @PostMapping("/scheduler/task")
  public @ResponseBody AttackResult submitTask(
      @RequestParam("taskDefinition") String taskDefinition,
      @RequestParam(required = false, defaultValue = "default-task") String taskName,
      @RequestParam(required = false, defaultValue = "DEFAULT") String triggerGroup,
      @RequestParam(required = false, defaultValue = "normal") String priority,
      @RequestParam(required = false, defaultValue = "immediate") String executionWindow) {

    try {
      log.info("Task submitted: name={}, group={}, priority={}", taskName, triggerGroup, priority);

      Scheduler scheduler = StdSchedulerFactory.getDefaultScheduler();
      scheduler.start();

      JobDetail jobDetail = newJob(SendQueueMessageJob.class).build();
      jobDetail.getJobDataMap().put("taskId", taskDefinition);
      jobDetail.getJobDataMap().put("jms.connection.factory", taskDefinition);

      Trigger trigger = TriggerBuilder.newTrigger().startNow().build();

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
   * <p>Accepts optional filter parameters. No task execution or
   * external configuration occurs on this path.
   *
   * @param taskName      task name filter (display only)
   * @param triggerGroup  trigger group scope (display only)
   * @param priority      priority filter (display only)
   */
  @PostMapping("/scheduler/status")
  public @ResponseBody AttackResult schedulerStatus(
      @RequestParam(required = false, defaultValue = "") String taskName,
      @RequestParam(required = false, defaultValue = "DEFAULT") String triggerGroup,
      @RequestParam(required = false, defaultValue = "all") String priority) {

    log.info("Scheduler status: task={}, group={}", taskName, triggerGroup);
    return failed(this)
        .output("Scheduler running. Group: " + triggerGroup
            + (taskName.isEmpty() ? "" : " | Task: " + taskName)
            + " | Priority filter: " + priority)
        .build();
  }

  /**
   * Returns execution history for completed tasks (decoy).
   *
   * <p>Accepts optional filter parameters. No task execution or
   * external configuration occurs on this path.
   *
   * @param taskName      task name filter (display only)
   * @param triggerGroup  trigger group filter (display only)
   * @param limit         max records to return (display only)
   */
  @PostMapping("/scheduler/history")
  public @ResponseBody AttackResult taskHistory(
      @RequestParam(required = false, defaultValue = "") String taskName,
      @RequestParam(required = false, defaultValue = "DEFAULT") String triggerGroup,
      @RequestParam(required = false, defaultValue = "10") String limit) {

    log.info("Task history: task={}, group={}, limit={}", taskName, triggerGroup, limit);
    return failed(this)
        .output("No execution history available"
            + (taskName.isEmpty() ? "." : " for task '" + taskName + "'."))
        .build();
  }

  public static class ScheduledTaskRunner implements Job {
    Logger log = LoggerFactory.getLogger(ScheduledTaskRunner.class.getName());

    @Override
    public void execute(JobExecutionContext jobExecutionContext) throws JobExecutionException {
      log.info("ScheduledTaskRunner executed");
      String taskId = jobExecutionContext.getJobDetail().getJobDataMap().getString("taskId");
      log.info("Task ID: {}", taskId);
    }
  }
}
