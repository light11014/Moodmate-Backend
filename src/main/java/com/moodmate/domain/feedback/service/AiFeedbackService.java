package com.moodmate.domain.feedback.service;

import com.moodmate.domain.diary.entity.Diary;
import com.moodmate.domain.diary.repository.DiaryRepository;
import com.moodmate.domain.feedback.dto.*;
import com.moodmate.domain.feedback.entity.AiFeedback;
import com.moodmate.domain.feedback.entity.DailyFeedbackUsage;
import com.moodmate.domain.feedback.repository.AiFeedbackRepository;
import com.moodmate.domain.feedback.repository.DailyFeedbackUsageRepository;
import com.moodmate.domain.user.entity.User;
import com.moodmate.domain.user.UserRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.nio.file.AccessDeniedException;
import java.time.LocalDate;
import java.util.List;
import java.util.Objects;
import java.util.stream.Collectors;

@Service
@RequiredArgsConstructor
@Transactional
@Slf4j
public class AiFeedbackService {

    private final AiFeedbackRepository aiFeedbackRepository;
    private final DailyFeedbackUsageRepository dailyUsageRepository;
    private final DiaryRepository diaryRepository;
    private final UserRepository userRepository;
    private final GeminiService geminiService;

    private static final int DAILY_FEEDBACK_LIMIT = 2;

    /**
     피드백 생성 (수정된 메소드)
     diaryId를 별도 파라미터로 받음
     */
    public FeedbackResponse createFeedback(Long userId, Long diaryId, FeedbackStyleRequest request) throws AccessDeniedException {
        // 사용자 조회
        User user = userRepository.findById(userId)
                .orElseThrow(() -> new IllegalArgumentException("사용자를 찾을 수 없습니다."));

        // 일기 조회 및 권한 확인
        Diary diary = diaryRepository.findById(diaryId)
                .orElseThrow(() -> new IllegalArgumentException("일기를 찾을 수 없습니다."));

        if (!Objects.equals(userId, diary.getUser().getId())) {
            throw new AccessDeniedException("해당 일기에 대한 권한이 없습니다.");
        }

        // 이미 해당 일기에 대한 피드백이 있는지 확인
        if (aiFeedbackRepository.findByDiaryId(diaryId).isPresent()) {
            throw new IllegalArgumentException("해당 일기에 대한 피드백이 이미 존재합니다.");
        }

        // 일일 사용량 확인 및 업데이트
        checkAndUpdateDailyUsage(userId);

        // AI 분석 실행
        String summary = geminiService.generateSummary(diary.getContent());
        String response = geminiService.generateFeedback(diary.getContent(), request.feedbackStyle());

        // 피드백 저장
        AiFeedback feedback = AiFeedback.builder()
                .user(user)
                .diary(diary)
                .summary(summary)
                .response(response)
                .feedbackStyle(request.feedbackStyle())
                .build();

        aiFeedbackRepository.save(feedback);
        log.info("피드백 생성 완료 - 사용자: {}, 일기: {}", userId, diaryId);

        return new FeedbackResponse(feedback);
    }

    @Transactional(readOnly = true)
    public FeedbackResponse getFeedback(Long userId, Long diaryId) throws AccessDeniedException {
        // 일기 조회 및 권한 확인
        Diary diary = diaryRepository.findById(diaryId)
                .orElseThrow(() -> new IllegalArgumentException("일기를 찾을 수 없습니다."));

        if (!Objects.equals(diary.getUser().getId(), userId)) {
            throw new AccessDeniedException("해당 일기에 대한 권한이 없습니다.");
        }

        // 피드백 조회
        AiFeedback feedback = aiFeedbackRepository.findByDiaryId(diaryId)
                .orElseThrow(() -> new IllegalArgumentException("해당 일기에 대한 피드백이 없습니다."));

        return new FeedbackResponse(feedback);
    }

    @Transactional(readOnly = true)
    public FeedbackHistoryResponse getFeedbackHistory(Long userId, LocalDate startDate, LocalDate endDate) {
        List<AiFeedback> feedbacks = aiFeedbackRepository.findByUserIdAndDateRange(userId, startDate, endDate);

        List<FeedbackHistoryItem> items = feedbacks.stream()
                .map(FeedbackHistoryItem::new)
                .toList();

        return new FeedbackHistoryResponse(startDate, endDate, items);
    }

    @Transactional(readOnly = true)
    public PeriodAnalysisResponse generatePeriodAnalysis(Long userId, PeriodAnalysisRequest request) {
        // 요청 검증
        request.validate();

        LocalDate startDate = request.getStartDate();
        LocalDate endDate = request.getEndDate();

        log.info("기간별 분석 시작 - 사용자: {}, 기간: {} ~ {}", userId, startDate, endDate);

        // 해당 기간의 피드백들 조회
        List<AiFeedback> feedbacks = aiFeedbackRepository.findByUserIdAndDateRange(userId, startDate, endDate);

        if (feedbacks.isEmpty()) {
            throw new IllegalArgumentException("해당 기간에 분석할 일기 데이터가 없습니다.");
        }

        // 요약들을 결합
        String combinedSummaries = feedbacks.stream()
                .map(AiFeedback::getSummary)
                .filter(Objects::nonNull)
                .collect(Collectors.joining("\n\n"));

        if (combinedSummaries.trim().isEmpty()) {
            throw new IllegalArgumentException("분석할 요약 데이터가 없습니다.");
        }

        try {
            // AI를 통한 종합 분석
            String periodSummary = geminiService.generatePeriodSummary(combinedSummaries, startDate, endDate);
            String emotionalPattern = geminiService.analyzeEmotionalPattern(combinedSummaries);
            String growthPattern = geminiService.analyzeGrowthPattern(combinedSummaries);
            String recommendations = geminiService.generateRecommendations(combinedSummaries);

            log.info("기간별 분석 완료 - 사용자: {}, 분석된 일기 수: {}", userId, feedbacks.size());

            return PeriodAnalysisResponse.create(
                    startDate,
                    endDate,
                    feedbacks.size(),
                    periodSummary,
                    emotionalPattern,
                    growthPattern,
                    recommendations
            );

        } catch (Exception e) {
            log.error("기간별 분석 중 오류 발생 - 사용자: {}, 오류: {}", userId, e.getMessage(), e);
            throw new RuntimeException("기간별 분석을 생성하는 중 오류가 발생했습니다: " + e.getMessage());
        }
    }

    @Transactional(readOnly = true)
    public DailyUsageResponse getDailyUsage(Long userId) {
        LocalDate today = LocalDate.now();
        DailyFeedbackUsage usage = dailyUsageRepository.findByUserIdAndUsageDate(userId, today)
                .orElse(null);

        int usedCount = (usage != null) ? usage.getUsageCount() : 0;
        int remainingCount = Math.max(0, DAILY_FEEDBACK_LIMIT - usedCount);

        return new DailyUsageResponse(usedCount, DAILY_FEEDBACK_LIMIT, remainingCount);
    }

    /**
     피드백 삭제
     */
    public void deleteFeedback(Long userId, Long diaryId) throws AccessDeniedException {
        // 일기 조회 및 권한 확인
        Diary diary = diaryRepository.findById(diaryId)
                .orElseThrow(() -> new IllegalArgumentException("일기를 찾을 수 없습니다."));

        if (!Objects.equals(diary.getUser().getId(), userId)) {
            throw new AccessDeniedException("해당 일기에 대한 권한이 없습니다.");
        }

        // 피드백 조회
        AiFeedback feedback = aiFeedbackRepository.findByDiaryId(diaryId)
                .orElseThrow(() -> new IllegalArgumentException("해당 일기에 대한 피드백이 없습니다."));

        // 피드백 소유자 확인 (추가 보안)
        if (!Objects.equals(feedback.getUser().getId(), userId)) {
            throw new AccessDeniedException("해당 피드백에 대한 권한이 없습니다.");
        }

        // 피드백 삭제
        aiFeedbackRepository.delete(feedback);
        log.info("피드백 삭제 완료 - 사용자: {}, 일기: {}, 피드백: {}", userId, diaryId, feedback.getId());

        // 일일 사용량 감소 (선택사항)
        decrementDailyUsage(userId, feedback.getCreated_at().toLocalDate());
    }

    private void checkAndUpdateDailyUsage(Long userId) {
        LocalDate today = LocalDate.now();

        DailyFeedbackUsage usage = dailyUsageRepository.findByUserIdAndUsageDate(userId, today)
                .orElse(null);

        if (usage == null) {
            // 오늘 첫 사용
            User user = userRepository.getReferenceById(userId);
            usage = DailyFeedbackUsage.builder()
                    .user(user)
                    .usageDate(today)
                    .usageCount(1)
                    .build();
            dailyUsageRepository.save(usage);
            log.info("새로운 일일 사용량 기록 생성 - 사용자: {}", userId);
        } else {
            // 사용량 확인
            if (usage.getUsageCount() >= DAILY_FEEDBACK_LIMIT) {
                log.warn("일일 사용량 초과 - 사용자: {}, 현재 사용량: {}", userId, usage.getUsageCount());
                throw new IllegalStateException("일일 피드백 사용량을 초과했습니다. (최대 " + DAILY_FEEDBACK_LIMIT + "회)");
            }
            // 사용량 증가
            usage.incrementUsage();
            dailyUsageRepository.save(usage);
            log.info("일일 사용량 업데이트 - 사용자: {}, 현재 사용량: {}", userId, usage.getUsageCount());
        }
    }

    /**
     피드백 삭제 시 일일 사용량 감소
     */
    private void decrementDailyUsage(Long userId, LocalDate feedbackDate) {
        // 오늘 생성된 피드백인 경우에만 사용량 감소
        if (feedbackDate.equals(LocalDate.now())) {
            DailyFeedbackUsage usage = dailyUsageRepository.findByUserIdAndUsageDate(userId, feedbackDate)
                    .orElse(null);

            if (usage != null && usage.getUsageCount() > 0) {
                // 사용량 감소를 위한 새로운 메소드 필요 (DailyFeedbackUsage 엔티티에 추가)
                usage.decrementUsage();
                dailyUsageRepository.save(usage);
                log.info("일일 사용량 감소 - 사용자: {}, 현재 사용량: {}", userId, usage.getUsageCount());
            }
        }
    }
}