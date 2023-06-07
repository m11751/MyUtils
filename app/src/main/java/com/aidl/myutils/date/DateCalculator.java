package com.aidl.myutils.date;

import java.time.DayOfWeek;
import java.time.LocalDate;
import java.time.Period;
import java.util.Scanner;

/**
 * 计算日期的函数
 */
public class DateCalculator {
    public static void main(String[] args) {
        dateCalculatorWithDayOfWeek(2015,2,10,8 * 365);
        dateCalculatorWithIntervals("2015.2.10","2023.5.11");
    }

    /**
     * 计算两个指定日期间相差的天数，带星期：日期：1990.9.16,SUNDAY,和日期：2023.5.11,THURSDAY,相隔天数：11925,合计：32年7月25天
     * @param dateStart 开始日期
     * @param dateEnd   结束日期
     */
    private static void dateCalculatorWithIntervals(String dateStart,String dateEnd){
        String[] parts = dateStart.split("\\.");
        int yearStart = Integer.parseInt(parts[0]);
        int monthStart = Integer.parseInt(parts[1]);
        int dayStart = Integer.parseInt(parts[2]);

        String[] partsEnd = dateEnd.split("\\.");
        int yearEnd = Integer.parseInt(partsEnd[0]);
        int monthEnd = Integer.parseInt(partsEnd[1]);
        int dayEnd = Integer.parseInt(partsEnd[2]);

        // 计算相隔天数
        LocalDate ldStart = LocalDate.of(yearStart, monthStart, dayStart);
        LocalDate ldEnd = LocalDate.of(yearEnd, monthEnd, dayEnd);
        int days = Math.abs((int)(ldStart.toEpochDay() - ldEnd.toEpochDay()));
        Period period = Period.between(ldStart, ldEnd);

        System.out.println("日期：" + dateStart + "," + ldStart.getDayOfWeek()
                + ",和日期：" + dateEnd + "," + ldEnd.getDayOfWeek() + "," +
                "相隔天数：" + days + ",合计：" +  period.getYears()
                + "年" + period.getMonths() + "月" + period.getDays() + "天");
    }

    /**
     * 计算指定日期增加天数后的日期，带星期:指定日期：2015-02-10,TUESDAY,增加2920天后的日期：2023-02-08,WEDNESDAY
     * @param year
     * @param month
     * @param day
     * @param intervals
     */
    private static void dateCalculatorWithDayOfWeek(int year,
                                                    int month,
                                                    int day,
                                                    int intervals) {
        // 读取指定日期
        LocalDate date = LocalDate.of(year, month, day);
        // 增加天数
        LocalDate newDate = date.plusDays(intervals);
        // 计算增加天数后的日期和星期
        DayOfWeek dayOfWeek = newDate.getDayOfWeek();
        // 输出结果
        System.out.println("指定日期：" + date + "," + date.getDayOfWeek()
        + "," + "增加" + intervals + "天" + "后的日期：" + newDate + "," + dayOfWeek);
    }
}

