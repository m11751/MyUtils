package com.aidl.myutils.base;

import android.util.Log;

/**
 * 脚本预防的工具类
 */
public class BaseUtils {
    /**
     * switch测试
     */
    public static void switchTest(int num){
        String str;
        switch (num/10){
            case 10:
            case 9:str = "优秀";break;
            case 8:
            case 7:str = "良好";break;
            case 6:str = "及格";break;
            default:str = "不及格";
        }
        Log.i("xwg","分数:" + num + "," + str);
    }
    /************使用枚举代替switch***************/
    enum Grade {
        EXCELLENT("优秀", 90, 100),
        GOOD("良好", 70, 89),
        PASS("及格", 60, 69),
        FAIL("不及格", 0, 59);

        private final String name;
        private final int minScore;
        private final int maxScore;

        Grade(String name, int minScore, int maxScore) {
            this.name = name;
            this.minScore = minScore;
            this.maxScore = maxScore;
        }

        public static Grade fromScore(int score) {
            for (Grade grade : values()) {
                if (score >= grade.minScore && score <= grade.maxScore) {
                    return grade;
                }
            }
            return null;
        }

        public String getName() {
            return name;
        }
    }

    public static void switchTest2(int num) {
        Grade grade = Grade.fromScore(num);
        String str = grade != null ? grade.getName() : "未知";
        Log.i("xwg", "分数:" + num + "," + str);
    }

}
