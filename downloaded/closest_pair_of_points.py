import tkinter as tk
from tkinter import ttk, filedialog, messagebox
import math
import random
import threading
import os

import matplotlib
matplotlib.use('TkAgg')
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
import matplotlib.pyplot as plt


class VisualFrame:
    def __init__(self, points, divide_line=None, closest_pair=None, depth=0, description=""):
        self.points = points
        self.divide_line = divide_line
        self.closest_pair = closest_pair
        self.depth = depth
        self.description = description


class ClosestPairSolver:
    
    def __init__(self):
        self.animation_frames = []
    
    def calculate_distance(self, point1, point2):
        x_diff = point1[0] - point2[0]
        y_diff = point1[1] - point2[1]
        return math.sqrt(x_diff**2 + y_diff**2)
    
    def save_frame(self, points, divide_line=None, closest_pair=None, depth=0, description=""):
        frame = VisualFrame(points, divide_line, closest_pair, depth, description)
        self.animation_frames.append(frame)
    
    def find_closest_bruteforce(self, points, depth):
        best_pair = None
        shortest_distance = float('inf')
        
        for i in range(len(points)):
            for j in range(i + 1, len(points)):
                distance = self.calculate_distance(points[i], points[j])
                if distance < shortest_distance:
                    shortest_distance = distance
                    best_pair = (points[i], points[j])
        
        description = f"Brute force: found distance = {shortest_distance:.2f}"
        self.save_frame(points, None, best_pair, depth, description)
        
        return best_pair, shortest_distance
    
    def check_middle_strip(self, points_x, points_y, min_distance, current_best, depth):
        middle_x = points_x[len(points_x) // 2][0]
        
        strip_points = [p for p in points_y if abs(p[0] - middle_x) < min_distance]
        
        best_pair = current_best
        best_distance = min_distance
        
        for i in range(len(strip_points)):
            for j in range(i + 1, min(i + 7, len(strip_points))):
                distance = self.calculate_distance(strip_points[i], strip_points[j])
                if distance < best_distance:
                    best_distance = distance
                    best_pair = (strip_points[i], strip_points[j])
                    description = f"Strip check: found closer pair = {best_distance:.2f}"
                    self.save_frame(points_x, middle_x, best_pair, depth, description)
        
        return best_pair, best_distance
    
    def find_closest_recursive(self, points_x, points_y, depth=0):
        num_points = len(points_x)
        
        middle_x = points_x[num_points // 2][0] if num_points > 1 else None
        description = f"Recursion depth {depth}: processing {num_points} points"
        self.save_frame(points_x, middle_x, None, depth, description)
        
        if num_points <= 3:
            return self.find_closest_bruteforce(points_x, depth)
        
        middle_index = num_points // 2
        left_x = points_x[:middle_index]
        right_x = points_x[middle_index:]
        
        left_set = set(left_x)
        left_y = [p for p in points_y if p in left_set]
        right_y = [p for p in points_y if p not in left_set]
        
        left_pair, left_distance = self.find_closest_recursive(left_x, left_y, depth + 1)
        right_pair, right_distance = self.find_closest_recursive(right_x, right_y, depth + 1)
        
        if left_distance <= right_distance:
            best_pair = left_pair
            min_distance = left_distance
        else:
            best_pair = right_pair
            min_distance = right_distance
        
        description = f"After conquering: best distance = {min_distance:.2f}"
        self.save_frame(points_x, points_x[middle_index][0], best_pair, depth, description)
        
        strip_pair, strip_distance = self.check_middle_strip(
            points_x, points_y, min_distance, best_pair, depth
        )
        
        if strip_distance < min_distance:
            return strip_pair, strip_distance
        else:
            return best_pair, min_distance
    
    def solve(self, points):
        self.animation_frames = []
        
        unique_points = list(set(points))
        points_sorted_x = sorted(unique_points, key=lambda p: (p[0], p[1]))
        points_sorted_y = sorted(unique_points, key=lambda p: (p[1], p[0]))
        
        if len(points_sorted_x) < 2:
            raise ValueError("Need at least 2 different points!")
        
        closest_pair, distance = self.find_closest_recursive(
            points_sorted_x, points_sorted_y, depth=0
        )
        
        description = f"FINAL RESULT: Closest distance = {distance:.4f}"
        self.save_frame(points_sorted_x, None, closest_pair, 0, description)
        
        return closest_pair, distance


def generate_sample_files():
    folder = filedialog.askdirectory(title="Choose folder to save sample files")
    if not folder:
        return
    
    try:
        for file_number in range(1, 11):
            num_points = random.randint(120, 400)
            
            points = []
            for _ in range(num_points):
                x = random.randint(0, 1000)
                y = random.randint(0, 1000)
                points.append((x, y))
            
            filename = os.path.join(folder, f'closest_pair_{file_number}.txt')
            with open(filename, 'w') as file:
                for x, y in points:
                    file.write(f"{x} {y}\n")
        
        messagebox.showinfo(
            "Success", 
            f"✓ Generated 10 sample files in:\n{folder}\n\n"
            f"Files: closest_pair_1.txt to closest_pair_10.txt"
        )
    
    except Exception as error:
        messagebox.showerror("Error", f"Could not generate files:\n{error}")


class ClosestPairGUI(tk.Tk):
    
    def __init__(self):
        super().__init__()
        self.title("Closest Pair of Points Visualizer")
        self.geometry("1000x700")
        
        self.solver = ClosestPairSolver()
        
        self.frames = []
        self.current_frame = 0
        self.is_playing = False
        self.animation_speed = 600
        
        self.create_interface()
    
    def create_interface(self):
        button_frame = ttk.Frame(self)
        button_frame.pack(side=tk.TOP, fill=tk.X, padx=10, pady=10)
        
        ttk.Button(
            button_frame, 
            text="📂 Load Points File", 
            command=self.load_points_file
        ).grid(row=0, column=0, padx=5)
        
        ttk.Button(
            button_frame, 
            text="📝 Generate 10 Sample Files", 
            command=generate_sample_files
        ).grid(row=0, column=1, padx=5)
        
        ttk.Button(
            button_frame, 
            text="▶️ Run Algorithm", 
            command=self.run_algorithm
        ).grid(row=0, column=2, padx=5)
        
        ttk.Button(
            button_frame, 
            text="⏯️ Play/Pause", 
            command=self.toggle_play
        ).grid(row=0, column=3, padx=5)
        
        ttk.Button(
            button_frame, 
            text="⏮️ Previous", 
            command=self.show_previous_frame
        ).grid(row=0, column=4, padx=5)
        
        ttk.Button(
            button_frame, 
            text="⏭️ Next", 
            command=self.show_next_frame
        ).grid(row=0, column=5, padx=5)
        
        status_frame = ttk.Frame(self)
        status_frame.pack(side=tk.BOTTOM, fill=tk.X, padx=10, pady=10)
        
        self.status_label = ttk.Label(
            status_frame, 
            text="Welcome! Load a points file or generate sample files to begin.",
            font=("Arial", 10)
        )
        self.status_label.pack(side=tk.LEFT)
        
        self.figure, self.axes = plt.subplots(figsize=(8, 6))
        self.canvas = FigureCanvasTkAgg(self.figure, master=self)
        self.canvas.get_tk_widget().pack(side=tk.TOP, fill=tk.BOTH, expand=True)
        self.axes.set_title('Closest Pair Visualization', fontsize=14)
    
    def load_points_file(self):
        file_path = filedialog.askopenfilename(
            title="Select Points File",
            filetypes=[("Text Files", "*.txt"), ("All Files", "*.*")]
        )
        
        if not file_path:
            return
        
        try:
            points = []
            with open(file_path, 'r') as file:
                for line in file:
                    line = line.strip()
                    if not line:
                        continue
                    
                    parts = line.split()
                    if len(parts) >= 2:
                        x = int(float(parts[0]))
                        y = int(float(parts[1]))
                        points.append((x, y))
            
            if len(points) < 2:
                messagebox.showerror("Error", "File must contain at least 2 points!")
                return
            
            self.loaded_points = points
            filename = os.path.basename(file_path)
            self.status_label.config(text=f"✓ Loaded {len(points)} points from {filename}")
            
            self.frames = []
            self.current_frame = 0
            
            self.display_points(points)
            
        except Exception as error:
            messagebox.showerror("Error", f"Could not read file:\n{error}")
    
    def display_points(self, points):
        self.axes.clear()
        
        x_coords = [p[0] for p in points]
        y_coords = [p[1] for p in points]
        
        self.axes.scatter(x_coords, y_coords, color='blue', s=30)
        self.axes.set_title('Loaded Points', fontsize=14)
        self.axes.set_xlabel('X')
        self.axes.set_ylabel('Y')
        self.axes.grid(True, alpha=0.3)
        
        self.canvas.draw()
    
    def run_algorithm(self):
        if not hasattr(self, 'loaded_points'):
            messagebox.showerror("Error", "Please load a points file first!")
            return
        
        def execute():
            try:
                self.status_label.config(text="⏳ Running algorithm...")
                
                closest_pair, distance = self.solver.solve(self.loaded_points)
                
                self.frames = self.solver.animation_frames
                self.current_frame = 0
                
                self.status_label.config(
                    text=f"✓ Complete! {len(self.frames)} steps recorded. "
                         f"Closest distance: {distance:.4f}"
                )
                
                self.render_frame(0)
                
            except Exception as error:
                messagebox.showerror("Error", f"Algorithm failed:\n{error}")
        
        thread = threading.Thread(target=execute, daemon=True)
        thread.start()
    
    def render_frame(self, frame_index):
        if not self.frames:
            return
        
        if frame_index < 0 or frame_index >= len(self.frames):
            return
        
        frame = self.frames[frame_index]
        self.axes.clear()
        
        x_coords = [p[0] for p in frame.points]
        y_coords = [p[1] for p in frame.points]
        self.axes.scatter(x_coords, y_coords, color='lightblue', s=30)
        
        if frame.divide_line is not None:
            y_min, y_max = min(y_coords), max(y_coords)
            self.axes.axvline(
                x=frame.divide_line, 
                color='gray', 
                linestyle='--', 
                linewidth=1.5,
                label='Division Line'
            )
        
        if frame.closest_pair and frame.closest_pair[0] is not None:
            point1, point2 = frame.closest_pair
            
            self.axes.plot(
                [point1[0], point2[0]], 
                [point1[1], point2[1]], 
                color='red', 
                linewidth=2.5,
                label='Closest Pair'
            )
            
            self.axes.scatter(
                [point1[0], point2[0]], 
                [point1[1], point2[1]], 
                color='red', 
                s=100, 
                zorder=5
            )
        
        title = f"Step {frame_index + 1}/{len(self.frames)} | " \
                f"Depth: {frame.depth} | {frame.description}"
        self.axes.set_title(title, fontsize=12)
        self.axes.set_xlabel('X')
        self.axes.set_ylabel('Y')
        self.axes.grid(True, alpha=0.3)
        self.axes.legend()
        
        self.canvas.draw()
        
        self.status_label.config(
            text=f"Frame {frame_index + 1}/{len(self.frames)} — {frame.description}"
        )
    
    def toggle_play(self):
        if not self.frames:
            messagebox.showinfo("Info", "Run the algorithm first!")
            return
        
        self.is_playing = not self.is_playing
        
        if self.is_playing:
            self.play_animation()
    
    def play_animation(self):
        if not self.is_playing:
            return
        
        self.render_frame(self.current_frame)
        
        self.current_frame += 1
        
        if self.current_frame >= len(self.frames):
            self.current_frame = len(self.frames) - 1
            self.is_playing = False
            return
        
        self.after(self.animation_speed, self.play_animation)
    
    def show_next_frame(self):
        if not self.frames:
            return
        
        self.is_playing = False
        self.current_frame = min(self.current_frame + 1, len(self.frames) - 1)
        self.render_frame(self.current_frame)
    
    def show_previous_frame(self):
        if not self.frames:
            return
        
        self.is_playing = False
        self.current_frame = max(self.current_frame - 1, 0)
        self.render_frame(self.current_frame)


if __name__ == '__main__':
    app = ClosestPairGUI()
    app.mainloop()
