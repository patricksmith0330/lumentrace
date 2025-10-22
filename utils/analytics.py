import time

def linregress(x, y):
    n = len(x)
    if n < 2:
        raise ValueError("Need at least 2 points")
    
    sum_x = sum(x)
    sum_y = sum(y)
    sum_xy = sum(x[i] * y[i] for i in range(n))
    sum_x2 = sum(x[i] ** 2 for i in range(n))
    
    denominator = n * sum_x2 - sum_x ** 2
    if denominator == 0:
        raise ValueError("Perfect horizontal line")
    
    slope = (n * sum_xy - sum_x * sum_y) / denominator
    intercept = (sum_y - slope * sum_x) / n
    
    return slope, intercept, None, None, None


def predict_battery_time(history):
    if len(history) < 2:
        return 'Insufficient data'
    
    timestamps = [h['timestamp'] for h in history]
    batteries = [h['battery'] for h in history]
    
    try:
        slope, intercept, _, _, _ = linregress(timestamps, batteries)
        
        if slope >= -0.001:
            return 'Charging or stable'
        else:
            time_to_zero = (0 - intercept) / slope
            time_remaining = time_to_zero - time.time()
            
            if time_remaining > 0:
                hours, remainder = divmod(time_remaining, 3600)
                minutes, _ = divmod(remainder, 60)
                return f'{int(hours)}h {int(minutes)}m remaining'
            else:
                return 'Very low'
                
    except ValueError:
        return 'Calculation error'